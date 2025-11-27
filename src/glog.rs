//! # Glog 读取器模块
//!
//! 本模块提供了 Glog 文件格式的主读取器实现。
//! 它会自动检测文件版本并使用相应的读取器处理日志数据。

use std::fs::File;
use std::io::BufReader;
use log::info;

use crate::error::{GlogError, Result, ReadResult};
use crate::version::{GLOG_RECOVERY_VERSION, GLOG_CIPHER_VERSION};
use crate::reader::{
    FileReader, MAGIC_NUMBER, SINGLE_LOG_CONTENT_MAX_LENGTH,
    read_safely,
    v3::FileReaderV3,
    v4::FileReaderV4,
};

/// Glog 读取器
///
/// 主入口读取器，负责解析文件头并根据版本号
/// 委托给相应的版本特定读取器处理日志数据
pub struct GlogReader {
    /// 内部文件读取器（版本特定）
    inner: Box<dyn FileReader>,
}

impl GlogReader {
    /// 创建新的 Glog 读取器
    ///
    /// # Arguments
    /// * `file_path` - 日志文件路径
    ///
    /// # Returns
    /// 返回新创建的 GlogReader 实例
    ///
    /// # Errors
    /// 如果文件无法打开或格式不正确，返回相应的错误
    pub fn new(file_path: &str) -> Result<Self> {
        Self::with_key(file_path, None)
    }

    /// 创建带加密密钥的 Glog 读取器
    ///
    /// # Arguments
    /// * `file_path` - 日志文件路径
    /// * `key` - 可选的服务器私钥（用于解密 V4 版本的加密日志）
    ///
    /// # Returns
    /// 返回新创建的 GlogReader 实例
    ///
    /// # Errors
    /// 如果文件无法打开或格式不正确，返回相应的错误
    pub fn with_key(file_path: &str, key: Option<String>) -> Result<Self> {
        let inner = open_internal(file_path, key)?;
        Ok(Self { inner })
    }

    /// 读取下一条日志
    ///
    /// # Arguments
    /// * `out_buf` - 输出缓冲区
    ///
    /// # Returns
    /// 返回读取结果
    pub fn read(&mut self, out_buf: &mut [u8]) -> Result<ReadResult> {
        self.inner.read(out_buf)
    }

    /// 获取单条日志的最大长度
    pub fn single_log_max_length() -> usize {
        SINGLE_LOG_CONTENT_MAX_LENGTH
    }
}

/// 打开 Glog 文件
///
/// 便捷函数，用于打开不需要解密的 Glog 文件
///
/// # Arguments
/// * `file_path` - 日志文件路径
///
/// # Returns
/// 返回 GlogReader 实例
pub fn open(file_path: &str) -> Result<GlogReader> {
    open_with_key(file_path, None)
}

/// 打开加密的 Glog 文件
///
/// # Arguments
/// * `file_path` - 日志文件路径
/// * `key` - 服务器私钥（十六进制字符串）
///
/// # Returns
/// 返回 GlogReader 实例
pub fn open_with_key(file_path: &str, key: Option<String>) -> Result<GlogReader> {
    let inner = open_internal(file_path, key)?;
    Ok(GlogReader { inner })
}

/// 内部打开文件的实现
///
/// # Arguments
/// * `file_path` - 日志文件路径
/// * `key` - 可选的服务器私钥
///
/// # Returns
/// 返回版本特定的文件读取器
fn open_internal(file_path: &str, key: Option<String>) -> Result<Box<dyn FileReader>> {
    // 第一次打开文件，读取版本信息
    let file = File::open(file_path)?;
    let size = file.metadata()?.len();
    let mut reader = BufReader::new(file);
    
    // 读取并验证魔数
    let mut magic = [0u8; 4];
    read_safely(&mut reader, 4, &mut magic)?;
    
    if magic != MAGIC_NUMBER {
        return Err(GlogError::MagicMismatch);
    }
    info!("魔数验证通过");

    // 读取版本号
    let mut version_buf = [0u8; 1];
    read_safely(&mut reader, 1, &mut version_buf)?;
    let version = version_buf[0];
    info!("文件版本: 0x{:02X}", version);

    // 关闭当前读取器
    drop(reader);
    
    // 第二次打开文件，供版本特定读取器使用
    let file = File::open(file_path)?;
    
    // 创建跳过头部的读取器
    let mut skip_reader = BufReader::new(file);
    let mut skip_buf = [0u8; 5]; // 跳过魔数(4) + 版本(1)
    read_safely(&mut skip_reader, 5, &mut skip_buf)?;

    // 根据版本号创建相应的读取器
    match version {
        GLOG_RECOVERY_VERSION => {
            let mut file_reader = FileReaderV3::from_reader(skip_reader, size);
            file_reader.read_remain_header()?;
            Ok(Box::new(file_reader))
        }
        GLOG_CIPHER_VERSION => {
            let mut file_reader = FileReaderV4::from_reader(skip_reader, size, key)?;
            file_reader.read_remain_header()?;
            Ok(Box::new(file_reader))
        }
        _ => Err(GlogError::UnsupportedVersion(version)),
    }
}
