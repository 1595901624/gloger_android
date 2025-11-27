mod error;
mod file_reader;
mod glog_reader;
mod proto;

use anyhow::Result;
use chrono::{TimeZone, Utc};
use clap::Parser;
use log::{error, info};
use prost::Message;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use walkdir::WalkDir;
use zip::ZipArchive;

use crate::glog_reader::GlogReader;
use crate::proto::clog::Log;

/// 服务端私钥，用于 ECDH 解密
const SVR_PRIV_KEY: &str = "1C74B66FCB1C54FD4386173CFAF3BC53C8DF6B89F799DE1A1E7CEBBC43CBFD38";

/// CLog 加密日志文件读取器
#[derive(Parser, Debug)]
#[command(name = "clog-reader")]
#[command(author = "Your Name")]
#[command(version = "0.1.0")]
#[command(about = "读取并解密 CLog 加密日志文件", long_about = None)]
struct Args {
    /// 日志 ZIP 压缩包路径
    #[arg(short = 'i', long = "input")]
    input: String,

    /// 日志类型过滤（逗号分隔，例如 "0,1,2"）
    #[arg(short = 't', long = "type", default_value = "")]
    log_type: String,

    /// 输出文件路径
    #[arg(short = 'o', long = "output", default_value = "log_output.txt")]
    output: String,
}

fn main() -> Result<()> {
    // 初始化日志记录器
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();

    // 解析日志类型过滤器
    let types: Vec<i32> = if args.log_type.is_empty() {
        Vec::new()
    } else {
        args.log_type
            .split(',')
            .filter_map(|s| s.trim().parse().ok())
            .collect()
    };

    info!("输入文件: {}", args.input);
    info!("日志类型过滤: {:?}", types);

    // 创建临时目录用于解压
    let temp_dir = TempDir::new()?;
    info!("临时目录: {:?}", temp_dir.path());

    // 解压日志文件
    unzip(&args.input, temp_dir.path())?;

    // 查找所有日志文件
    let mut log_files: Vec<PathBuf> = Vec::new();
    log_files.extend(get_glog_files(temp_dir.path())?);
    log_files.extend(get_mmap_files(temp_dir.path())?);

    info!("找到 {} 个日志文件", log_files.len());

    // 创建输出文件
    let output_path = PathBuf::from(&args.output);
    let mut output_file = File::create(&output_path)?;

    // 处理每个日志文件
    for log_file in &log_files {
        info!("正在处理: {:?}", log_file);
        if let Err(e) = read_logs(log_file, &types, &mut output_file) {
            error!("处理 {:?} 时出错: {}", log_file, e);
        }
    }

    info!("输出已写入: {:?}", output_path);
    Ok(())
}

/// 解压 ZIP 文件到目标目录
fn unzip(zip_path: &str, dest_dir: &Path) -> Result<()> {
    let file = File::open(zip_path)?;
    let mut archive = ZipArchive::new(file)?;

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let outpath = match file.enclosed_name() {
            Some(path) => dest_dir.join(path),
            None => continue,
        };

        if file.name().ends_with('/') {
            fs::create_dir_all(&outpath)?;
        } else {
            if let Some(p) = outpath.parent() {
                if !p.exists() {
                    fs::create_dir_all(p)?;
                }
            }
            let mut outfile = File::create(&outpath)?;
            std::io::copy(&mut file, &mut outfile)?;
        }
    }

    Ok(())
}

/// 获取所有匹配 async-YYYYMMDD.glog 模式的 .glog 文件
fn get_glog_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut files: Vec<PathBuf> = WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| {
            let name = e.file_name().to_string_lossy();
            name.ends_with(".glog") && is_async_glog_file(&name)
        })
        .map(|e| e.path().to_path_buf())
        .collect();

    // 按文件名中的日期降序排序
    files.sort_by(|a, b| {
        let name_a = a.file_name().unwrap().to_string_lossy();
        let name_b = b.file_name().unwrap().to_string_lossy();
        name_b.cmp(&name_a)
    });

    Ok(files)
}

/// 检查文件名是否匹配 async-YYYYMMDD.glog 模式
fn is_async_glog_file(name: &str) -> bool {
    if !name.starts_with("async-") || !name.ends_with(".glog") {
        return false;
    }
    let date_part = &name[6..name.len() - 5];
    date_part.len() == 8 && date_part.chars().all(|c| c.is_ascii_digit())
}

/// 获取所有 .glogmmap 文件
fn get_mmap_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut files: Vec<PathBuf> = WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| e.file_name().to_string_lossy().ends_with(".glogmmap"))
        .map(|e| e.path().to_path_buf())
        .collect();

    // 按修改时间降序排序
    files.sort_by(|a, b| {
        let time_a = fs::metadata(a).and_then(|m| m.modified()).ok();
        let time_b = fs::metadata(b).and_then(|m| m.modified()).ok();
        time_b.cmp(&time_a)
    });

    Ok(files)
}

/// 从文件中读取并解析日志
fn read_logs(file_path: &Path, types: &[i32], output: &mut File) -> Result<()> {
    let mut reader = GlogReader::new(file_path, Some(SVR_PRIV_KEY))?;
    let mut log_num = 0;
    let mut buf = vec![0u8; glog_reader::SINGLE_LOG_CONTENT_MAX_LENGTH];

    loop {
        match reader.read(&mut buf) {
            Ok(len) if len > 0 => {
                let content = &buf[..len];
                log_num += 1;

                // 解码 protobuf
                match Log::decode(content) {
                    Ok(log) => {
                        // 如果指定了类型则进行过滤
                        if types.is_empty() || types.contains(&log.r#type) {
                            let formatted = format_log(&log);
                            writeln!(output, "{}", formatted)?;
                        }
                    }
                    Err(e) => {
                        error!("解码日志 {} 失败: {}", log_num, e);
                    }
                }
            }
            Ok(_) => {
                // len <= 0，文件结束或错误
                break;
            }
            Err(e) => {
                error!("读取错误: {}", e);
                break;
            }
        }
    }

    info!("从 {:?} 处理的日志总数: {}", file_path, log_num);
    Ok(())
}

/// 将日志条目格式化为人类可读的字符串
fn format_log(log: &Log) -> String {
    let timestamp = log
        .timestamp
        .parse::<i64>()
        .map(|ts| {
            Utc.timestamp_millis_opt(ts)
                .single()
                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S%.3f").to_string())
                .unwrap_or_else(|| log.timestamp.clone())
        })
        .unwrap_or_else(|_| log.timestamp.clone());

    let level = get_log_level(log.log_level);

    format!(
        "{} [{}] [{}] {{{}:{}}} -- {}",
        timestamp, level, log.tag, log.pid, log.tid, log.msg
    )
}

/// 获取日志级别字符串
fn get_log_level(level: i32) -> &'static str {
    match level {
        0 => "Info",
        1 => "Debug",
        2 => "Verbose",
        3 => "Warn",
        4 => "Error",
        _ => "Unknown",
    }
}
