//! # CLog Reader 库
//!
//! `clog_reader` 是一个用于读取和解析 Glog 格式日志文件的 Rust 库。
//!
//! ## 功能特性
//!
//! - 支持 Glog V3（恢复版本）和 V4（加密版本）文件格式
//! - 支持 zlib 压缩的日志数据解压
//! - 支持 AES-128-CFB 加密的日志数据解密
//! - 使用 secp256k1 椭圆曲线进行 ECDH 密钥交换
//! - 支持 Protobuf 格式的日志消息解析
//!
//! ## 快速开始
//!
//! ```rust,no_run
//! use clog_reader::{glog, proto::Log, error::ReadResult};
//!
//! fn main() -> anyhow::Result<()> {
//!     // 打开日志文件（带解密密钥）
//!     let mut reader = glog::open_with_key(
//!         "path/to/logfile.glog",
//!         Some("your_private_key_hex".to_string())
//!     )?;
//!
//!     // 读取日志
//!     let mut buf = vec![0u8; glog::GlogReader::single_log_max_length()];
//!     
//!     loop {
//!         match reader.read(&mut buf)? {
//!             ReadResult::Success(len) => {
//!                 // 解析 protobuf 日志
//!                 let log = Log::decode_from(&buf[..len])?;
//!                 println!("{}", log.format());
//!             }
//!             ReadResult::Eof => break,
//!             ReadResult::NeedRecover(code) => {
//!                 eprintln!("需要恢复，错误码: {}", code);
//!                 continue;
//!             }
//!         }
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! ## 模块结构
//!
//! - [`error`] - 错误类型定义
//! - [`version`] - Glog 版本常量
//! - [`reader`] - 文件读取器实现
//! - [`glog`] - 主读取器接口
//! - [`proto`] - Protobuf 日志消息定义

/// 错误处理模块
pub mod error;

/// 版本常量模块
pub mod version;

/// 文件读取器模块
pub mod reader;

/// Glog 读取器模块
pub mod glog;

/// Protobuf 日志消息模块
pub mod proto;

// 重新导出常用类型
pub use error::{GlogError, Result, ReadResult};
pub use glog::{GlogReader, open, open_with_key};
pub use proto::Log;

/// 库版本信息
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// 库名称
pub const NAME: &str = env!("CARGO_PKG_NAME");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn test_name() {
        assert_eq!(NAME, "clog-reader");
    }
}
