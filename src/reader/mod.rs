//! # 文件读取器基础模块
//!
//! 本模块定义了文件读取器的基础特征和共享功能，
//! 包括读取辅助函数和解压缩功能。

pub mod v3;
pub mod v4;

use std::io::{Read, Cursor};
use flate2::read::ZlibDecoder;
use crate::error::{GlogError, Result, ReadResult};
use log::info;

/// 单条日志内容的最大长度 (16KB)
pub const SINGLE_LOG_CONTENT_MAX_LENGTH: usize = 16 * 1024;

/// Glog 文件的魔数
/// 用于标识文件是否为有效的 Glog 文件
pub const MAGIC_NUMBER: [u8; 4] = [0x1B, 0xAD, 0xC0, 0xDE];

/// 同步标记
/// 用于在文件中标识日志条目的边界，支持从损坏的文件中恢复
pub const SYNC_MARKER: [u8; 8] = [0xB7, 0xDB, 0xE7, 0xDB, 0x80, 0xAD, 0xD9, 0x57];

/// 压缩模式枚举
/// 定义了日志数据支持的压缩方式
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CompressMode {
    /// 无压缩
    None,
    /// Zlib 压缩
    Zlib,
}

/// 加密模式枚举
/// 定义了日志数据支持的加密方式
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EncryptMode {
    /// 无加密
    None,
    /// AES CFB-128 加密
    Aes,
}

/// 文件读取器特征
///
/// 定义了所有 Glog 文件读取器必须实现的接口
pub trait FileReader {
    /// 读取剩余的文件头信息
    ///
    /// # Returns
    /// 成功返回 `Ok(())`，失败返回相应的错误
    fn read_remain_header(&mut self) -> Result<()>;

    /// 读取下一条日志
    ///
    /// # Arguments
    /// * `out_buf` - 输出缓冲区，用于存储读取的日志内容
    ///
    /// # Returns
    /// 返回 `ReadResult` 枚举，表示读取结果
    fn read(&mut self, out_buf: &mut [u8]) -> Result<ReadResult>;

    /// 获取当前读取位置
    fn position(&self) -> u64;

    /// 获取剩余可读取的字节数
    fn space_left(&self) -> u64;
}

/// 安全读取函数
///
/// 从输入流中安全地读取指定数量的字节到缓冲区
///
/// # Arguments
/// * `input` - 输入流（实现 Read 特征）
/// * `expected` - 期望读取的字节数
/// * `filled` - 用于存储读取数据的缓冲区
///
/// # Returns
/// 成功返回读取的字节数，失败返回错误
///
/// # Errors
/// 如果可用字节数少于期望值或读取失败，返回 `UnexpectedEof` 错误
pub fn read_safely<R: Read>(input: &mut R, expected: usize, filled: &mut [u8]) -> Result<usize> {
    let mut total_read = 0;
    while total_read < expected {
        match input.read(&mut filled[total_read..expected]) {
            Ok(0) => {
                return Err(GlogError::UnexpectedEof {
                    expected,
                    available: total_read,
                });
            }
            Ok(n) => {
                total_read += n;
            }
            Err(e) => return Err(GlogError::Io(e)),
        }
    }
    Ok(total_read)
}

/// 读取小端序 16 位无符号整数
///
/// # Arguments
/// * `input` - 输入流
///
/// # Returns
/// 返回读取的 u16 值
pub fn read_u16_le<R: Read>(input: &mut R) -> Result<u16> {
    let mut buf = [0u8; 2];
    read_safely(input, 2, &mut buf)?;
    Ok(u16::from_le_bytes(buf))
}

/// 解压缩数据
///
/// 使用 zlib 算法解压缩数据
///
/// # Arguments
/// * `in_buf` - 输入的压缩数据
/// * `out_buf` - 输出缓冲区，用于存储解压后的数据
///
/// # Returns
/// 成功返回解压后的数据长度，失败返回错误
pub fn decompress(in_buf: &[u8], out_buf: &mut [u8]) -> Result<usize> {
    // 创建一个 ZlibDecoder 来解压数据
    // 注意：Java 代码使用的是 raw deflate (无 zlib header)
    // 所以我们使用 DeflateDecoder 而不是 ZlibDecoder
    let cursor = Cursor::new(in_buf);
    let mut decoder = ZlibDecoder::new(cursor);
    
    let mut total_read = 0;
    loop {
        match decoder.read(&mut out_buf[total_read..]) {
            Ok(0) => break,
            Ok(n) => {
                total_read += n;
                if total_read >= out_buf.len() {
                    break;
                }
            }
            Err(e) => {
                return Err(GlogError::DecompressError(e.to_string()));
            }
        }
    }
    
    info!("解压缩完成，输入 {} 字节，输出 {} 字节", in_buf.len(), total_read);
    Ok(total_read)
}

/// 解压缩数据 (使用 raw deflate)
///
/// 使用 raw deflate 算法解压缩数据（无 zlib/gzip 头部）
///
/// # Arguments
/// * `in_buf` - 输入的压缩数据
/// * `out_buf` - 输出缓冲区，用于存储解压后的数据
///
/// # Returns
/// 成功返回解压后的数据长度，失败返回错误
pub fn decompress_raw(in_buf: &[u8], out_buf: &mut [u8]) -> Result<usize> {
    use flate2::read::DeflateDecoder;
    
    let cursor = Cursor::new(in_buf);
    let mut decoder = DeflateDecoder::new(cursor);
    
    let mut total_read = 0;
    loop {
        match decoder.read(&mut out_buf[total_read..]) {
            Ok(0) => break,
            Ok(n) => {
                total_read += n;
                if total_read >= out_buf.len() {
                    break;
                }
            }
            Err(e) => {
                return Err(GlogError::DecompressError(e.to_string()));
            }
        }
    }
    
    info!("Raw 解压缩完成，输入 {} 字节，输出 {} 字节", in_buf.len(), total_read);
    Ok(total_read)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_magic_number() {
        assert_eq!(MAGIC_NUMBER, [0x1B, 0xAD, 0xC0, 0xDE]);
    }

    #[test]
    fn test_sync_marker() {
        assert_eq!(SYNC_MARKER.len(), 8);
    }

    #[test]
    fn test_read_u16_le() {
        let data = [0x34, 0x12]; // 0x1234 in little endian
        let mut cursor = Cursor::new(&data);
        let result = read_u16_le(&mut cursor).unwrap();
        assert_eq!(result, 0x1234);
    }
}
