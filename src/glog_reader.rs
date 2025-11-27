use crate::error::{ClogError, Result};
use crate::file_reader::{FileReader, FileReaderV3, FileReaderV4};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

/// 单条日志内容最大长度 16 * 1024
pub const SINGLE_LOG_CONTENT_MAX_LENGTH: usize = 16384;

/// glog 文件头部的魔数
pub const MAGIC_NUMBER: [u8; 4] = [0x1B, 0xAD, 0xC0, 0xDE];

/// 日志条目之间的同步标记
pub const SYNC_MARKER: [u8; 8] = [0xB7, 0xDB, 0xE7, 0xDB, 0x80, 0xAD, 0xD9, 0x57];

/// GLog 文件读取器
pub struct GlogReader {
    reader: Box<dyn FileReader>,
}

impl GlogReader {
    /// 创建新的 GlogReader
    ///
    /// # 参数
    /// - file_path: 日志文件路径
    /// - key: 可选的服务端私钥（用于解密 V4 格式）
    pub fn new(file_path: &Path, key: Option<&str>) -> Result<Self> {
        let file = File::open(file_path)?;
        let mut buf_reader = BufReader::new(file);

        // 读取并验证魔数
        let mut magic = [0u8; 4];
        buf_reader.read_exact(&mut magic)?;

        if magic != MAGIC_NUMBER {
            return Err(ClogError::MagicMismatch);
        }

        // 读取版本号
        let mut version = [0u8; 1];
        buf_reader.read_exact(&mut version)?;

        let reader: Box<dyn FileReader> = match version[0] {
            3 => {
                // V3 版本：仅支持压缩
                let mut reader = FileReaderV3::new(buf_reader)?;
                reader.read_header()?;
                Box::new(reader)
            }
            4 => {
                // V4 版本：支持加密 + 压缩
                let mut reader = FileReaderV4::new(buf_reader, key)?;
                reader.read_header()?;
                Box::new(reader)
            }
            v => return Err(ClogError::VersionMismatch(v)),
        };

        Ok(Self { reader })
    }

    /// 读取单条日志
    ///
    /// # 参数
    /// - buf: 输出缓冲区
    ///
    /// # 返回
    /// 成功时返回读取的字节数，0 表示已到达文件末尾
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.reader.read(buf)
    }
}
