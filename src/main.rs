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

use std::fs::{self, File};
use std::io::{Write, BufWriter};
use std::path::{Path, PathBuf};
use std::process::exit;
use anyhow::{Context, Result};
use clap::Parser;
// use log::{info, warn, error};
use walkdir::WalkDir;
use zip::ZipArchive;

use clog_reader::{
    glog::{open_with_key, GlogReader},
    proto::Log,
    error::ReadResult,
};

/// 服务器私钥（用于解密加密的日志）
const SVR_PRIV_KEY: &str = "1C74B66FCB1C54FD4386173CFAF3BC53C8DF6B89F799DE1A1E7CEBBC43CBFD38";

/// CLog Reader 命令行参数
#[derive(Parser, Debug)]
#[command(name = "clog-reader")]
#[command(author = "CLog Reader Team")]
#[command(version = "0.1.0")]
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
}

fn main() -> Result<()> {
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
        println!("日志类型过滤器: {:?}", types);
    }

    // 创建临时目录
    let temp_dir = tempfile::tempdir()
        .context("创建临时目录失败")?;
    let temp_path = temp_dir.path();
    println!("临时目录路径: {}", temp_path.display());

    // 解压缩 ZIP 文件
    unzip(&args.input, temp_path)
        .context("解压缩失败")?;

    // 收集日志文件
    let mut log_files: Vec<PathBuf> = Vec::new();
    log_files.extend(get_glog_files(temp_path)?);
    log_files.extend(get_mmap_files(temp_path)?);

    println!("找到 {} 个日志文件", log_files.len());

    // 创建输出文件
    let output_path = PathBuf::from(&args.output);
    let output_file = File::create(&output_path)
        .context(format!("创建输出文件失败: {}", output_path.display()))?;
    let mut writer = BufWriter::new(output_file);

    // 处理每个日志文件
    for log_file in &log_files {
        println!("正在处理: {}", log_file.display());
        match read_logs(log_file, &types, &mut writer) {
            Ok(count) => {
                println!("成功读取 {} 条日志", count);
            }
            Err(e) => {
                eprintln!("读取日志失败 {}: {}", log_file.display(), e);
            }
        }
    }

    writer.flush()?;
    println!("日志输出已保存到: {}", output_path.display());

    Ok(())
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
    let file = File::open(zip_path)
        .context(format!("无法打开 ZIP 文件: {}", zip_path))?;
    
    let mut archive = ZipArchive::new(file)
        .context("无法读取 ZIP 文件")?;

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

    println!("解压缩完成，共 {} 个文件", archive.len());
    Ok(())
}

/// 获取目录下所有 .glog 文件
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
        .filter(|e| {
            let name = e.file_name().to_string_lossy();
            name.ends_with(".glog") && 
            name.starts_with("async-") &&
            name.len() >= 18 // async-YYYYMMdd.glog
        })
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

/// 从 glog 文件名中提取日期
///
/// # Arguments
/// * `path` - 文件路径
///
/// # Returns
/// 返回日期字符串（YYYYMMdd）
fn extract_date_from_glog_name(path: &Path) -> String {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(|n| {
            if n.len() >= 14 {
                n[6..14].to_string() // 提取 YYYYMMdd
            } else {
                String::new()
            }
        })
        .unwrap_or_default()
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
/// * `writer` - 输出写入器
///
/// # Returns
/// 返回读取的日志条数
fn read_logs<W: Write>(file_path: &Path, types: &[i32], writer: &mut W) -> Result<usize> {
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

                        // 格式化并写入日志
                        let formatted = log.format();
                        writeln!(writer, "{}", formatted)?;
                        log_count += 1;
                    }
                    Err(_) => {
                        // eprintln!("解析日志失败: {}", e);
                    }
                }
            }
            Ok(ReadResult::Eof) => {
                println!("读取完成");
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
                eprintln!("读取错误: {}", e);
                break;
            }
        }
    }

    println!("共读取 {} 条日志", log_count);
    // Ok(log_count)
    exit(0)
}
