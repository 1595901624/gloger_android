//! # CLog Reader 命令行工具
//!
//! 这是一个用于读取和解析 Glog 格式日志文件的命令行工具。
//! 支持从 ZIP 压缩包中提取日志文件并解析输出。
//!
//! ## 使用方法
//!
//! ```bash
//! # 基本用法：解析日志 ZIP 文件
//! clog-reader -i <日志.zip>
//!
//! # 按日志类型过滤
//! clog-reader -i <日志.zip> -t 0,1,2
//!
//! # 显示帮助信息
//! clog-reader -h
//! ```

use anyhow::{Context, Result};
use clap::Parser;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::exit;
use std::time::Instant;
// use log::{info, warn, error};
use walkdir::WalkDir;
use zip::ZipArchive;

use clog_reader::{
    error::ReadResult,
    glog::{open_with_key, GlogReader},
    proto::Log,
    print_flush, eprint_flush,
};

/// 服务器私钥（用于解密加密的日志）
const SVR_PRIV_KEY: &str = "1C74B66FCB1C54FD4386173CFAF3BC53C8DF6B89F799DE1A1E7CEBBC43CBFD38";

/// CLog Reader 命令行参数
#[derive(Parser, Debug)]
#[command(name = "clog-reader")]
#[command(author = "CLog Reader Team")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "读取和解析 Glog 格式日志文件的工具", long_about = None)]
struct Args {
    /// 日志 ZIP 文件路径
    #[arg(short = 'i', long = "input", required = true)]
    input: String,

    /// 过滤日志类型（逗号分隔，如 0,1,2）
    #[arg(short = 't', long = "type", default_value = "")]
    log_types: String,

    /// 输出文件路径（默认为当前目录下的 log_output.txt）
    #[arg(short = 'o', long = "output", default_value = "log_output.txt")]
    output: String,

    /// 按主进程和插件分开输出（在输出文件名后添加 _async / _plugin_async）
    #[arg(long)]
    split: bool,

    /// 合并输出时按日志的毫秒时间戳升序排序（需在内存中暂存日志）
    #[arg(long, conflicts_with = "split")]
    sort_by_time: bool,
}

fn main() -> Result<()> {
    let start_time = Instant::now();

    // 初始化日志
    // env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
    //     .format_timestamp(None)
    //     .init();

    // 解析命令行参数
    let args = Args::parse();

    // 解析日志类型过滤器
    let types: Vec<i32> = if args.log_types.is_empty() {
        Vec::new()
    } else {
        args.log_types
            .split(',')
            .filter_map(|s| s.trim().parse::<i32>().ok())
            .collect()
    };

    if !types.is_empty() {
        print_flush!("日志类型过滤器: {:?}", types);
    }

    // 创建临时目录
    let temp_dir = tempfile::tempdir().context("创建临时目录失败")?;
    let temp_path = temp_dir.path().to_path_buf();
    print_flush!("临时目录路径: {}", temp_path.display());

    // 解压缩 ZIP 文件
    unzip(&args.input, &temp_path).context("解压缩失败")?;

    // 收集日志文件
    let mut log_files: Vec<PathBuf> = Vec::new();
    log_files.extend(get_glog_files(&temp_path)?);
    log_files.extend(get_mmap_files(&temp_path)?);

    print_flush!("找到 {} 个日志文件", log_files.len());

    // 调试：如果没有找到日志文件，列出临时目录内容
    if log_files.is_empty() {
        print_flush!("未找到日志文件，列出临时目录内容:");
        for entry in WalkDir::new(&temp_path).into_iter().filter_map(|e| e.ok()) {
            print_flush!("  {}", entry.path().display());
        }
    }

    // 默认合并输出；分开输出时，同一进程的归档和 mmap 使用同一个写入器。
    let output_path = PathBuf::from(&args.output);
    let output_paths = if args.split {
        vec![
            grouped_output_path(&output_path, "async"),
            grouped_output_path(&output_path, "plugin_async"),
        ]
    } else {
        vec![output_path]
    };
    let mut writers = Vec::new();
    for path in &output_paths {
        let file = File::create(path)
            .context(format!("创建输出文件失败: {}", path.display()))?;
        writers.push(BufWriter::new(file));
    }

    let mut pending_logs = Vec::new();

    // 处理每个日志文件
    for log_file in &log_files {
        print_flush!("正在处理: {}", log_file.display());
        let writer_index = usize::from(args.split && is_plugin_log(log_file));
        let result = read_logs(log_file, &types, |log| {
            if args.sort_by_time {
                pending_logs.push(log);
            } else {
                writeln!(writers[writer_index], "{}", log.format())?;
            }
            Ok(())
        });
        match result {
            Ok(count) => {
                print_flush!("成功读取 {} 条日志", count);
            }
            Err(e) => {
                eprint_flush!("读取日志失败 {}: {}", log_file.display(), e);
            }
        }
    }

    if args.sort_by_time {
        write_sorted_logs(&mut pending_logs, &mut writers[0])?;
        print_flush!("已按时间戳排序输出 {} 条日志", pending_logs.len());
    }

    for (writer, path) in writers.iter_mut().zip(&output_paths) {
        writer.flush()?;
        print_flush!("日志输出已保存到: {}", path.display());
    }

    let elapsed = start_time.elapsed();
    print_flush!("程序运行时间: {:.2}秒", elapsed.as_secs_f64());

    // 统一使用 exit(0) 退出，确保所有资源正确释放后进程结束
    exit(0);
}

/// 稳定排序整个日志记录，保留多行消息和相同时间戳的原始顺序。
fn write_sorted_logs<W: Write>(logs: &mut [Log], writer: &mut W) -> Result<()> {
    logs.sort_by_cached_key(|log| {
        let timestamp = log.timestamp.parse::<i64>().ok();
        (timestamp.is_none(), timestamp.unwrap_or_default())
    });
    let invalid_count = logs.iter().filter(|log| log.timestamp.parse::<i64>().is_err()).count();
    if invalid_count > 0 {
        eprint_flush!("{} 条日志的时间戳无效，已保留并放在输出末尾", invalid_count);
    }
    for log in logs {
        writeln!(writer, "{}", log.format())?;
    }
    Ok(())
}

/// 仅按文件名区分插件，避免父目录名影响归类。
fn is_plugin_log(path: &Path) -> bool {
    path.file_name()
        .map(|name| name.to_string_lossy().starts_with("plugin_"))
        .unwrap_or(false)
}

/// 在扩展名前添加分组名称，并保留输出目录。
fn grouped_output_path(path: &Path, group: &str) -> PathBuf {
    let mut name = path.file_stem().unwrap_or_default().to_os_string();
    name.push("_");
    name.push(group);
    if let Some(extension) = path.extension() {
        name.push(".");
        name.push(extension);
    }
    path.with_file_name(name)
}

/// 解压缩 ZIP 文件
///
/// # Arguments
/// * `zip_path` - ZIP 文件路径
/// * `dest_dir` - 目标目录
///
/// # Returns
/// 成功返回 Ok(())
fn unzip(zip_path: &str, dest_dir: &Path) -> Result<()> {
    let file = File::open(zip_path).context(format!("无法打开 ZIP 文件: {}", zip_path))?;

    let mut archive = ZipArchive::new(file).context("无法读取 ZIP 文件")?;

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;

        // 构造输出路径
        let out_path = match file.enclosed_name() {
            Some(path) => dest_dir.join(path),
            None => continue,
        };

        if file.name().ends_with('/') {
            // 创建目录
            fs::create_dir_all(&out_path)?;
        } else {
            // 创建父目录
            if let Some(parent) = out_path.parent() {
                if !parent.exists() {
                    fs::create_dir_all(parent)?;
                }
            }

            // 提取文件
            let mut out_file = File::create(&out_path)?;
            std::io::copy(&mut file, &mut out_file)?;
        }
    }

    print_flush!("解压缩完成，共 {} 个文件", archive.len());
    Ok(())
}

/// 获取目录下所有以 async-YYYYMMdd.glog 结尾的归档文件（支持插件前缀）
///
/// 按文件名中的日期排序（升序）
///
/// # Arguments
/// * `dir_path` - 目录路径
///
/// # Returns
/// 返回排序后的文件路径列表
fn get_glog_files(dir_path: &Path) -> Result<Vec<PathBuf>> {
    let mut files: Vec<PathBuf> = WalkDir::new(dir_path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| !extract_date_from_glog_name(e.path()).is_empty())
        .map(|e| e.path().to_path_buf())
        .collect();

    // 按日期排序（从文件名中提取日期）
    files.sort_by(|a, b| {
        let date_a = extract_date_from_glog_name(a);
        let date_b = extract_date_from_glog_name(b);
        date_a.cmp(&date_b)
    });

    Ok(files)
}

/// 从以 async-YYYYMMdd.glog 结尾的文件名中提取日期，忽略插件前缀
///
/// # Arguments
/// * `path` - 文件路径
///
/// # Returns
/// 返回日期字符串（YYYYMMdd）
fn extract_date_from_glog_name(path: &Path) -> String {
    path.file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| n.strip_suffix(".glog"))
        .and_then(|n| n.rsplit_once("async-"))
        .map(|(_, date)| date)
        .filter(|date| date.len() == 8 && date.bytes().all(|b| b.is_ascii_digit()))
        .map(str::to_owned)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_sort_is_opt_in_and_conflicts_with_split() {
        assert!(!Args::try_parse_from(["clog-reader", "-i", "logs.zip"]).unwrap().sort_by_time);
        assert!(Args::try_parse_from(["clog-reader", "-i", "logs.zip", "--sort-by-time"]).unwrap().sort_by_time);
        let error = Args::try_parse_from([
            "clog-reader", "-i", "logs.zip", "--sort-by-time", "--split",
        ]).unwrap_err();
        assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn sorts_numeric_timestamps_stably_and_preserves_whole_messages() -> Result<()> {
        let mut logs: Vec<Log> = [
            ("10", "later"),
            ("invalid", "invalid first"),
            ("2", "main\ncontinued"),
            ("2", "plugin"),
            ("-1", "earliest"),
            ("", "invalid second"),
            ("9223372036854775808", "overflow"),
        ].into_iter().map(|(timestamp, msg)| Log {
            timestamp: timestamp.to_owned(),
            msg: msg.to_owned(),
            ..Log::default()
        }).collect();
        let mut output = Vec::new();
        write_sorted_logs(&mut logs, &mut output)?;
        assert_eq!(
            logs.iter().map(|log| log.msg.as_str()).collect::<Vec<_>>(),
            ["earliest", "main\ncontinued", "plugin", "later", "invalid first", "invalid second", "overflow"]
        );
        let expected: String = logs.iter().map(|log| format!("{}\n", log.format())).collect();
        assert_eq!(output, expected.as_bytes());
        write_sorted_logs(&mut [], &mut Vec::new())?;
        Ok(())
    }

    #[test]
    fn split_is_opt_in() {
        assert!(!Args::try_parse_from(["clog-reader", "-i", "logs.zip"]).unwrap().split);
        assert!(Args::try_parse_from(["clog-reader", "-i", "logs.zip", "--split"]).unwrap().split);
    }

    #[test]
    fn split_groups_archives_and_mmap_by_filename() {
        for name in ["plugin_async-20261113.glog", "plugin_async.glogmmap"] {
            assert!(is_plugin_log(&Path::new("nested").join(name)));
        }
        for name in ["async-20261113.glog", "async.glogmmap"] {
            assert!(!is_plugin_log(&Path::new("plugin_directory").join(name)));
        }
        for (input, expected) in [
            ("log_output.txt", "log_output_async.txt"),
            ("logs/output", "logs/output_async"),
            ("logs/日志.output.txt", "logs/日志.output_async.txt"),
        ] {
            assert_eq!(grouped_output_path(Path::new(input), "async"), Path::new(expected));
        }
        assert_eq!(
            grouped_output_path(Path::new("logs/output.txt"), "plugin_async"),
            Path::new("logs/output_plugin_async.txt")
        );
    }

    #[test]
    fn collects_main_and_plugin_archives_in_date_order() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let nested = dir.path().join("plugin");
        fs::create_dir(&nested)?;
        for name in [
            "async-20261112.glog",
            "plugin_async-20261110.glog",
            "插件_async-20261111.glog",
            "sync-20261112173425699.glog",
            "async-2026111.glog",
            "async-202611120.glog",
            "async-2026abcd.glog",
            "async-20261112.glog.bak",
            "plugin_async.glogmmap",
        ] {
            File::create(nested.join(name))?;
        }
        fs::create_dir(nested.join("async-20261109.glog"))?;

        assert_eq!(
            get_glog_files(dir.path())?,
            vec![
                nested.join("plugin_async-20261110.glog"),
                nested.join("插件_async-20261111.glog"),
                nested.join("async-20261112.glog"),
            ]
        );
        assert_eq!(
            get_mmap_files(dir.path())?,
            vec![nested.join("plugin_async.glogmmap")]
        );
        Ok(())
    }

    #[test]
    fn extracts_date_from_suffix_with_any_prefix() {
        for name in [
            "async-20261112.glog",
            "plugin_async-20261112.glog",
            "插件_async-20261112.glog",
            "async-prefix_async-20261112.glog",
        ] {
            assert_eq!(extract_date_from_glog_name(Path::new(name)), "20261112");
        }
        for name in ["short", "sync-20261112173425699.glog", "async-2026abcd.glog"] {
            assert!(extract_date_from_glog_name(Path::new(name)).is_empty());
        }
    }
}

/// 获取目录下所有 .glogmmap 文件
///
/// 按最后修改时间排序（降序）
///
/// # Arguments
/// * `dir_path` - 目录路径
///
/// # Returns
/// 返回排序后的文件路径列表
fn get_mmap_files(dir_path: &Path) -> Result<Vec<PathBuf>> {
    let mut files: Vec<(PathBuf, std::time::SystemTime)> = WalkDir::new(dir_path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| e.file_name().to_string_lossy().ends_with(".glogmmap"))
        .filter_map(|e| {
            let path = e.path().to_path_buf();
            e.metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .map(|time| (path, time))
        })
        .collect();

    // 按修改时间降序排序
    files.sort_by(|a, b| b.1.cmp(&a.1));

    Ok(files.into_iter().map(|(path, _)| path).collect())
}

/// 读取日志文件
///
/// # Arguments
/// * `file_path` - 日志文件路径
/// * `types` - 日志类型过滤器
/// * `on_log` - 处理每条解密、解码且符合类型过滤条件的完整日志
///
/// # Returns
/// 返回读取的日志条数
fn read_logs<F>(file_path: &Path, types: &[i32], mut on_log: F) -> Result<usize>
where
    F: FnMut(Log) -> Result<()>,
{
    let file_path_str = file_path.to_string_lossy().to_string();

    // 使用私钥打开日志文件
    let mut reader = open_with_key(&file_path_str, Some(SVR_PRIV_KEY.to_string()))
        .context(format!("打开日志文件失败: {}", file_path.display()))?;

    let mut log_count = 0;
    let buf_len = GlogReader::single_log_max_length();
    let mut buf = vec![0u8; buf_len];

    loop {
        match reader.read(&mut buf) {
            Ok(ReadResult::Success(len)) => {
                if len == 0 {
                    continue;
                }

                // 解析 protobuf 日志
                match Log::decode_from(&buf[..len]) {
                    Ok(log) => {
                        // 检查类型过滤
                        if !types.is_empty() && !types.contains(&log.log_type) {
                            continue;
                        }

                        on_log(log)?;
                        log_count += 1;
                    }
                    Err(_) => {
                        // eprintln!("解析日志失败: {}", e);
                    }
                }
            }
            Ok(ReadResult::Eof) => {
                print_flush!("读取完成");
                break;
            }
            Ok(ReadResult::NeedRecover(code)) => {
                // eprintln!("需要恢复，错误码: {}", code);
                if code == -1 {
                    break;
                }
                continue;
            }
            Err(e) => {
                eprint_flush!("读取错误: {}", e);
                break;
            }
        }
    }

    print_flush!("共读取 {} 条日志", log_count);
    Ok(log_count)
}
