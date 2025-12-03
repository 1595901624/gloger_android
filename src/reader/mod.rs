//! # 文件读取器基础模块
//!
//! 本模块定义了文件读取器的基础特征和共享功能，
//! 包括读取辅助函数和解压缩功能。
//!
//! ## 重要说明
//!
//! Java 版本使用的 jzlib Inflater 具有以下特性：
//! - 使用 `WrapperType.NONE` (raw deflate 格式，无 zlib/gzip 头部)
//! - Inflater 对象在整个文件读取过程中复用，保持内部状态（字典等）
//! - 每次调用使用 `Z_SYNC_FLUSH` 模式
//!
//! 这意味着多个日志块实际上是作为一个连续的 deflate 流压缩的，
//! 因此 Rust 实现也需要使用有状态的流式解压器。

pub mod v3;
pub mod v4;

use std::io::{self, Read, Cursor, Write};
use flate2::read::ZlibDecoder;
use flate2::Decompress;
use flate2::FlushDecompress;
// use flate2::Status;
use crate::error::{GlogError, Result, ReadResult};
// use log::{info, debug};

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

/// 有状态的 Raw Deflate 解压器
///
/// 模拟 Java 的 jzlib Inflater 行为：
/// - 使用 raw deflate 格式（无 zlib/gzip 头部）
/// - 在多次调用之间保持内部状态（字典等）
/// - 支持 SYNC_FLUSH 模式
///
/// # 设计说明
///
/// Java 的 Glog 实现将多个日志块作为一个连续的 deflate 流压缩，
/// 每次写入后使用 SYNC_FLUSH 确保数据可以立即读取，但 zlib 字典等状态是持续的。
/// 这个结构体复制了这种行为。
pub struct StatefulInflater {
    /// flate2 的底层解压器
    decompressor: Decompress,
    /// 累计输入字节数（用于调试）
    total_in: u64,
    /// 累计输出字节数（用于调试）
    total_out: u64,
}

impl StatefulInflater {
    /// 创建新的有状态解压器
    ///
    /// 使用 raw deflate 格式（对应 Java 的 WrapperType.NONE）
    pub fn new() -> Self {
        // false 表示 raw deflate（无 zlib 头部）
        // 这对应 Java 的 JZlib.WrapperType.NONE
        Self {
            decompressor: Decompress::new(false),
            total_in: 0,
            total_out: 0,
        }
    }

    /// 解压数据块
    ///
    /// 模拟 Java 的 `inflater.inflate(Z_SYNC_FLUSH)` 行为
    ///
    /// # Arguments
    /// * `in_buf` - 输入的压缩数据
    /// * `out_buf` - 输出缓冲区
    ///
    /// # Returns
    /// 成功返回解压后的数据长度
    pub fn decompress(&mut self, in_buf: &[u8], out_buf: &mut [u8]) -> Result<usize> {
        let before_in = self.decompressor.total_in();
        let before_out = self.decompressor.total_out();

        // 使用 FlushDecompress::Sync 对应 Z_SYNC_FLUSH
        let _ = self.decompressor.decompress(
            in_buf,
            out_buf,
            FlushDecompress::Sync
        ).map_err(|e| GlogError::DecompressError(format!("decompress error: {}", e)))?;

        let consumed = (self.decompressor.total_in() - before_in) as usize;
        let produced = (self.decompressor.total_out() - before_out) as usize;

        self.total_in += consumed as u64;
        self.total_out += produced as u64;

        // debug!(
        //     "解压: 输入 {} 字节 (已消费 {}), 输出 {} 字节, 状态: {:?}",
        //     in_buf.len(),
        //     consumed,
        //     produced,
        //     status
        // );

        // 检查是否消费了所有输入
        if consumed != in_buf.len() {
            // debug!(
            //     "警告: 输入未完全消费: 提供 {} 字节, 消费 {} 字节",
            //     in_buf.len(),
            //     consumed
            // );
        }

        Ok(produced)
    }

    /// 重置解压器状态
    ///
    /// 在某些情况下需要重置（例如文件损坏后的恢复）
    #[allow(dead_code)]
    pub fn reset(&mut self) {
        self.decompressor.reset(false);
        println!("解压器已重置, 之前累计: 输入 {} 字节, 输出 {} 字节", self.total_in, self.total_out);
        io::stdout().flush().unwrap();
        self.total_in = 0;
        self.total_out = 0;
    }

    /// 获取累计输入字节数
    #[allow(dead_code)]
    pub fn total_in(&self) -> u64 {
        self.total_in
    }

    /// 获取累计输出字节数
    #[allow(dead_code)]
    pub fn total_out(&self) -> u64 {
        self.total_out
    }
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
    
    println!("解压缩完成，输入 {} 字节，输出 {} 字节", in_buf.len(), total_read);
    io::stdout().flush().unwrap();
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
    
    println!("Raw 解压缩完成，输入 {} 字节，输出 {} 字节", in_buf.len(), total_read);
    io::stdout().flush().unwrap();
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
