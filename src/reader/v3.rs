//! # Glog V3 版本文件读取器
//!
//! 本模块实现了 Glog 文件格式 V3 版本的读取器。
//! V3 版本的主要特点是在每条日志中添加同步标记，支持从损坏的文件中恢复数据。
//!
//! ## 文件格式 (所有长度使用小端序存储)
//!
//! ```text
//! +-----------------------------------------------------------------+
//! |                         magic number (4)                        |
//! +----------------+----------------+-------------------------------+
//! |   version (1)  |  mode set (1)  |     proto name length (2)     |
//! +----------------+----------------+-------------------------------+
//! |       proto name (0...)       ...
//! +-----------------------------------------------------------------+
//! |       sync marker (8)     ...                                   |
//! +-----------------------------------------------------------------+
//! |                                       ... sync marker           |
//! +=================================+===============================+
//! |         log length (2)          |
//! +---------------------------------+-------------------------------+
//! |                           log data (0...)         ...
//! +-----------------------------------------------------------------+
//! |       sync marker (8)     ...                                   |
//! +-----------------------------------------------------------------+
//! |                                       ... sync marker           |
//! +-----------------------------------------------------------------+
//! |         log length (2)         |
//! +--------------------------------+--------------------------------+
//! |                           log data (0...)         ...
//! +-----------------------------------------------------------------+
//! |       sync marker (8)     ...                                   |
//! +-----------------------------------------------------------------+
//! |                                       ... sync marker           |
//! +------------------------------------------------------------------
//! |                              ...
//! +-----------------------------------------------------------------+
//! ```
//!
//! ## 重要说明
//!
//! Java 版本的实现使用有状态的 Inflater，在整个文件读取过程中保持 zlib 字典状态。
//! 这意味着多个日志块实际上是作为一个连续的 deflate 流压缩的。
//! 因此本实现也使用 `StatefulInflater` 来保持解压状态。

use std::io::{Read, BufReader};
use std::fs::File;
use log::{info, warn};

use crate::error::{GlogError, Result, ReadResult};
use super::{
    FileReader, CompressMode, EncryptMode, 
    SYNC_MARKER, SINGLE_LOG_CONTENT_MAX_LENGTH,
    read_safely, read_u16_le, StatefulInflater,
};

/// V3 版本文件读取器
///
/// 实现了 Glog 恢复版本 (V3) 的日志读取功能
///
/// ## 解压状态
///
/// 内置有状态的解压器，模拟 Java 的 jzlib Inflater 行为
pub struct FileReaderV3<R: Read> {
    /// 输入流
    input: R,
    /// 压缩模式
    compress_mode: CompressMode,
    /// 加密模式
    #[allow(dead_code)]
    encrypt_mode: EncryptMode,
    /// 当前读取位置
    position: u64,
    /// 文件总大小
    size: u64,
    /// 有状态的解压器（模拟 Java 的 Inflater 行为）
    inflater: StatefulInflater,
}

impl FileReaderV3<BufReader<File>> {
    /// 从文件创建 V3 读取器
    ///
    /// # Arguments
    /// * `file` - 打开的文件句柄
    /// * `size` - 文件大小
    ///
    /// # Returns
    /// 返回新创建的 FileReaderV3 实例
    pub fn new(file: File, size: u64) -> Result<Self> {
        let reader = BufReader::new(file);
        Ok(Self {
            input: reader,
            compress_mode: CompressMode::None,
            encrypt_mode: EncryptMode::None,
            position: 5, // 跳过魔数(4字节) + 版本(1字节)
            size,
            inflater: StatefulInflater::new(),
        })
    }
}

impl<R: Read> FileReaderV3<R> {
    /// 从任意 Read 实现创建 V3 读取器
    ///
    /// # Arguments
    /// * `input` - 输入流
    /// * `size` - 数据总大小
    ///
    /// # Returns
    /// 返回新创建的 FileReaderV3 实例
    #[allow(dead_code)]
    pub fn from_reader(input: R, size: u64) -> Self {
        Self {
            input,
            compress_mode: CompressMode::None,
            encrypt_mode: EncryptMode::None,
            position: 5,
            size,
            inflater: StatefulInflater::new(),
        }
    }

    /// 计算日志存储大小
    ///
    /// # Arguments
    /// * `len` - 日志数据长度
    ///
    /// # Returns
    /// 返回包含长度字段和同步标记的总存储大小
    fn log_store_size(&self, len: usize) -> usize {
        // 日志长度(2字节) + 日志数据 + 同步标记(8字节)
        2 + len + 8
    }
}

impl<R: Read> FileReader for FileReaderV3<R> {
    /// 读取剩余的文件头信息
    ///
    /// 解析模式设置字节、协议名称和同步标记
    fn read_remain_header(&mut self) -> Result<()> {
        // 读取模式设置字节
        let mut ms_buf = [0u8; 1];
        read_safely(&mut self.input, 1, &mut ms_buf)?;
        let ms = ms_buf[0];

        // 解析压缩模式 (高4位)
        match ms >> 4 {
            0 => self.compress_mode = CompressMode::None,
            1 => self.compress_mode = CompressMode::Zlib,
            _ => return Err(GlogError::IllegalCompressMode(ms >> 4)),
        }

        // 解析加密模式 (低4位)
        match ms & 0x0F {
            0 => self.encrypt_mode = EncryptMode::None,
            1 => self.encrypt_mode = EncryptMode::Aes,
            _ => return Err(GlogError::IllegalEncryptMode(ms & 0x0F)),
        }

        // info!("压缩模式: {:?}, 加密模式: {:?}", self.compress_mode, self.encrypt_mode);

        // 读取协议名称长度
        let proto_name_len = read_u16_le(&mut self.input)?;
        info!("协议名称长度: {}", proto_name_len);

        // 检查是否有足够的数据
        let required = proto_name_len as usize + 8;
        let available = self.space_left() as usize;
        if available < required {
            return Err(GlogError::UnexpectedEof {
                expected: required,
                available,
            });
        }

        // 读取协议名称
        let mut name = vec![0u8; proto_name_len as usize];
        read_safely(&mut self.input, proto_name_len as usize, &mut name)?;
        let proto_name = String::from_utf8_lossy(&name);
        info!("协议名称: {}", proto_name);

        // 读取并验证同步标记
        let mut sync_marker = [0u8; 8];
        read_safely(&mut self.input, 8, &mut sync_marker)?;

        if sync_marker != SYNC_MARKER {
            return Err(GlogError::SyncMarkerMismatch);
        }

        // 更新位置：魔数(4) + 版本(1) + 模式(1) + 协议名称长度(2) + 协议名称 + 同步标记(8)
        self.position = 4 + 1 + 1 + 2 + proto_name_len as u64 + 8;
        info!("读取头部完成，当前位置: {}", self.position);

        Ok(())
    }

    /// 读取下一条日志
    ///
    /// # Arguments
    /// * `out_buf` - 输出缓冲区
    ///
    /// # Returns
    /// 返回读取结果
    fn read(&mut self, out_buf: &mut [u8]) -> Result<ReadResult> {
        // 检查是否有足够的数据读取最小的日志条目
        if self.space_left() < self.log_store_size(1) as u64 {
            return Ok(ReadResult::Eof);
        }

        // 读取日志长度
        let log_length = read_u16_le(&mut self.input)? as usize;
        self.position += 2;

        // 检查是否有足够的数据
        let required = log_length + 8;
        let available = self.space_left() as usize;
        if available < required {
            return Err(GlogError::UnexpectedEof {
                expected: required,
                available,
            });
        }

        // 验证日志长度
        if log_length == 0 || log_length > SINGLE_LOG_CONTENT_MAX_LENGTH {
            warn!("无效的日志长度: {}，位置: {}", log_length, self.position);
            return Ok(ReadResult::NeedRecover(-2));
        }

        info!("日志长度: {}", log_length);

        // 读取日志数据
        let mut buf = vec![0u8; log_length];
        read_safely(&mut self.input, log_length, &mut buf)?;
        self.position += log_length as u64;

        // 根据压缩模式处理数据
        let final_length = match self.compress_mode {
            CompressMode::Zlib => {
                // 使用有状态的解压器解压数据
                self.inflater.decompress(&buf, out_buf)?
            }
            CompressMode::None => {
                // 直接复制数据
                let copy_len = log_length.min(out_buf.len());
                out_buf[..copy_len].copy_from_slice(&buf[..copy_len]);
                copy_len
            }
        };

        // 读取并验证同步标记
        let mut sync_marker = [0u8; 8];
        read_safely(&mut self.input, 8, &mut sync_marker)?;

        if sync_marker != SYNC_MARKER {
            warn!("同步标记不匹配，位置: {}", self.position);
            return Ok(ReadResult::NeedRecover(-3));
        }
        self.position += 8;

        Ok(ReadResult::Success(final_length))
    }

    /// 获取当前读取位置
    fn position(&self) -> u64 {
        self.position
    }

    /// 获取剩余可读取的字节数
    fn space_left(&self) -> u64 {
        if self.size <= self.position {
            0
        } else {
            self.size - self.position
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_store_size() {
        let reader = FileReaderV3::<std::io::Cursor<Vec<u8>>> {
            input: std::io::Cursor::new(vec![]),
            compress_mode: CompressMode::None,
            encrypt_mode: EncryptMode::None,
            position: 0,
            size: 0,
            inflater: StatefulInflater::new(),
        };
        
        // 日志长度(2) + 数据(10) + 同步标记(8) = 20
        assert_eq!(reader.log_store_size(10), 20);
    }
}
