//! # Glog V4 版本文件读取器
//!
//! 本模块实现了 Glog 文件格式 V4 版本的读取器。
//! V4 版本的主要特点是支持 AES CFB-128 加密，使用 ECDH 密钥交换。
//!
//! ## 加密方案
//! - 使用 secp256k1 椭圆曲线进行 ECDH 密钥交换
//! - 客户端公钥以压缩格式(33字节)存储
//! - 使用 AES-128-CFB 模式进行对称加密
//!
//! ## 文件格式 (所有长度使用小端序存储)
//!
//! ```text
//! +-----------------------------------------------------------------+
//! |                         magic number (4)                        |
//! +----------------+-------------------------------+----------------+
//! |   version (1)  |     proto name length (2)     |
//! +----------------+-------------------------------+----------------+
//! |       proto name (0...)       ...
//! +-----------------------------------------------------------------+
//! |       sync marker (8)     ...                                   |
//! +-----------------------------------------------------------------+
//! |                                       ... sync marker           |
//! +================+================================================+
//! |  mode set (1)  |          optional: AES random iv (16)
//! +----------------+------------------------------------------------+
//! |                              ... AES random iv                  |
//! +-----------------------------------------------------------------+
//! |       optional: client ecc public key (33, compressed)
//! +-----------------------------------------------------------------+
//! |                              ... client ecc public key          |
//! +-------------------------------+---------------------------------+
//! |        log length (2)         |
//! +-------------------------------+----------------------------------
//! |                           log data (0...)         ...
//! +-----------------------------------------------------------------+
//! |       sync marker (8)     ...                                   |
//! +-----------------------------------------------------------------+
//! |                                       ... sync marker           |
//! +-----------------------------------------------------------------+
//! |                              ...
//! +-----------------------------------------------------------------+
//! ```
//!
//! ## 重要说明
//!
//! Java 版本的实现使用有状态的 Inflater，在整个文件读取过程中保持 zlib 字典状态。
//! 这意味着多个日志块实际上是作为一个连续的 deflate 流压缩的。
//! 因此本实现也使用 `StatefulInflater` 来保持解压状态。

use std::fs::File;
use std::io::{BufReader, Read, Write};
// use log::{info, warn};

use aes::cipher::AsyncStreamCipher;
use aes::Aes128;
use cfb_mode::cipher::KeyIvInit;
use cfb_mode::Decryptor;
use k256::{
    elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint}, PublicKey,
    SecretKey,
};
use std::collections::HashMap;

use super::{
    read_safely, read_u16_le, CompressMode,
    EncryptMode, FileReader,
    StatefulInflater, SINGLE_LOG_CONTENT_MAX_LENGTH, SYNC_MARKER,
};
use crate::error::{GlogError, ReadResult, Result};

/// AES CFB 解密器类型别名
type Aes128CfbDec = Decryptor<Aes128>;

/// V4 版本文件读取器
///
/// 实现了 Glog 加密版本 (V4) 的日志读取功能
/// 支持 AES-128-CFB 加密和 zlib 压缩
///
/// ## 解压状态
///
/// 内置有状态的解压器，模拟 Java 的 jzlib Inflater 行为
pub struct FileReaderV4<R: Read> {
    /// 输入流
    input: R,
    /// 服务器私钥（十六进制字符串）
    svr_pri_key: Option<String>,
    /// 服务器 EC 私钥
    svr_ec_pri_key: Option<SecretKey>,
    /// 当前读取位置
    position: u64,
    /// 文件总大小
    size: u64,
    /// 有状态的解压器（模拟 Java 的 Inflater 行为）
    inflater: StatefulInflater,
    /// ECDH 共享密钥缓存（压缩公钥 -> 共享密钥）
    shared_key_cache: HashMap<[u8; 33], Vec<u8>>,
}

impl FileReaderV4<BufReader<File>> {
    /// 从文件创建 V4 读取器
    ///
    /// # Arguments
    /// * `file` - 打开的文件句柄
    /// * `size` - 文件大小
    /// * `key` - 可选的服务器私钥（十六进制字符串）
    ///
    /// # Returns
    /// 返回新创建的 FileReaderV4 实例
    pub fn new(file: File, size: u64, key: Option<String>) -> Result<Self> {
        let reader = BufReader::new(file);
        let svr_ec_pri_key = if let Some(ref k) = key {
            Some(prepare_svr_pri_key(k)?)
        } else {
            None
        };

        Ok(Self {
            input: reader,
            svr_pri_key: key,
            svr_ec_pri_key,
            position: 5, // 跳过魔数(4字节) + 版本(1字节)
            size,
            inflater: StatefulInflater::new(),
            shared_key_cache: HashMap::new(),
        })
    }
}

impl<R: Read> FileReaderV4<R> {
    /// 从任意 Read 实现创建 V4 读取器
    ///
    /// # Arguments
    /// * `input` - 输入流
    /// * `size` - 数据总大小
    /// * `key` - 可选的服务器私钥
    ///
    /// # Returns
    /// 返回新创建的 FileReaderV4 实例
    #[allow(dead_code)]
    pub fn from_reader(input: R, size: u64, key: Option<String>) -> Result<Self> {
        let svr_ec_pri_key = if let Some(ref k) = key {
            Some(prepare_svr_pri_key(k)?)
        } else {
            None
        };

        Ok(Self {
            input,
            svr_pri_key: key,
            svr_ec_pri_key,
            position: 5,
            size,
            inflater: StatefulInflater::new(),
            shared_key_cache: HashMap::new(),
        })
    }

    /// 计算日志存储大小
    ///
    /// # Arguments
    /// * `len` - 日志数据长度
    /// * `cipher` - 是否加密
    ///
    /// # Returns
    /// 返回包含所有字段的总存储大小
    #[allow(dead_code)]
    fn log_store_size(&self, len: usize, cipher: bool) -> usize {
        // 模式(1) + 日志长度(2) + 日志数据 + 同步标记(8) + (如果加密: IV(16) + 压缩公��(33))
        1 + 2 + len + 8 + if cipher { 16 + 33 } else { 0 }
    }

    /// 获取 ECDH 共享密钥（使用压缩公钥作为缓存 key）
    ///
    /// # Arguments
    /// * `compressed_pub_key` - 压缩的客户端公钥（33字节）
    ///
    /// # Returns
    /// 返回共享密钥的字节数组
    fn get_shared_key_cached(&mut self, compressed_pub_key: &[u8; 33]) -> Result<Vec<u8>> {
        // 检查缓存
        if let Some(cached_key) = self.shared_key_cache.get(compressed_pub_key) {
            return Ok(cached_key.clone());
        }

        let svr_key = self.svr_ec_pri_key.as_ref()
            .ok_or(GlogError::CipherNotReady)?;

        // 解压缩公钥
        let client_pub_key = decompress_public_key(compressed_pub_key)?;

        // 将客户端公钥转换为 PublicKey
        let client_ec_pub_key = prepare_client_pub_key(&client_pub_key)?;

        // 执行 ECDH 密钥交换
        let shared_secret = k256::ecdh::diffie_hellman(
            svr_key.to_nonzero_scalar(),
            client_ec_pub_key.as_affine()
        );

        let key_bytes = shared_secret.raw_secret_bytes().to_vec();

        // 缓存结果
        self.shared_key_cache.insert(*compressed_pub_key, key_bytes.clone());

        Ok(key_bytes)
    }

    /// 解密数据
    ///
    /// 使用 ECDH 共享密钥和 AES-128-CFB 算法解密数据
    ///
    /// # Arguments
    /// * `compressed_pub_key` - 压缩的客户端公钥（33字节）
    /// * `iv` - 初始化向量（16字节）
    /// * `encrypt` - 加密的数据
    ///
    /// # Returns
    /// 返回解密后的数据
    fn decrypt(&mut self, compressed_pub_key: &[u8; 33], iv: &[u8], encrypt: &[u8]) -> Result<Vec<u8>> {
        // 获取共享密钥（使用压缩公钥缓存）
        let aes_key = self.get_shared_key_cached(compressed_pub_key)?;
        
        // 只使用前16字节作为 AES-128 密钥
        let key_bytes: [u8; 16] = aes_key[..16]
            .try_into()
            .map_err(|_| GlogError::DecryptError("密钥长度错误".to_string()))?;
        
        let iv_bytes: [u8; 16] = iv
            .try_into()
            .map_err(|_| GlogError::DecryptError("IV 长度错误".to_string()))?;

        // 创建 AES-CFB 解密器并解密数据
        let mut plain = encrypt.to_vec();
        let decryptor = Aes128CfbDec::new(&key_bytes.into(), &iv_bytes.into());
        decryptor.decrypt(&mut plain);

        Ok(plain)
    }
}

impl<R: Read> FileReader for FileReaderV4<R> {
    /// 读取剩余的文件头信息
    ///
    /// 解析协议名称长度、协议名称和同步标记
    fn read_remain_header(&mut self) -> Result<()> {
        // 读取协议名称长度
        let proto_name_len = read_u16_le(&mut self.input)?;
        
        // 读取协议名称
        let mut name = vec![0u8; proto_name_len as usize];
        read_safely(&mut self.input, proto_name_len as usize, &mut name)?;
        let _proto_name = String::from_utf8_lossy(&name);

        // 读取并验证同步标记
        let mut sync_marker = [0u8; 8];
        read_safely(&mut self.input, 8, &mut sync_marker)?;

        if sync_marker != SYNC_MARKER {
            return Err(GlogError::SyncMarkerMismatch);
        }

        // 更新位置：魔数(4) + 版本(1) + 协议名称长度(2) + 协议名称 + 同步标记(8)
        self.position = 4 + 1 + 2 + proto_name_len as u64 + 8;

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
        // 检查是否有足够的数据（最小需要: 模式(1) + 长度(2) + 同步标记(8)）
        if self.space_left() < (1 + 2 + 8) as u64 {
            return Ok(ReadResult::Eof);
        }

        // 读取模式设置字节
        let mut ms_buf = [0u8; 1];
        read_safely(&mut self.input, 1, &mut ms_buf)?;
        let ms = ms_buf[0];

        // 解析压缩模式 (高4位)
        let compress_mode = match ms >> 4 {
            1 => CompressMode::None,
            2 => CompressMode::Zlib,
            _ => {
                // eprintln!("非法压缩模式: {}", ms >> 4);
                return Ok(ReadResult::NeedRecover(-2));
            }
        };

        // 解析加密模式 (低4位)
        let encrypt_mode = match ms & 0x0F {
            1 => EncryptMode::None,
            2 => EncryptMode::Aes,
            _ => {
                // eprintln!("非法加密模式: {}", ms & 0x0F);
                return Ok(ReadResult::NeedRecover(-3));
            }
        };

        // info!("压缩模式: {:?}, 加密模式: {:?}", compress_mode, encrypt_mode);

        // 如果需要解密但没有密钥，返回错误
        if encrypt_mode == EncryptMode::Aes && self.svr_pri_key.is_none() {
            return Err(GlogError::CipherNotReady);
        }

        self.position += 1;

        let final_length = if encrypt_mode == EncryptMode::Aes {
            // 读取 IV (16字节)
            let mut iv = [0u8; 16];
            read_safely(&mut self.input, 16, &mut iv)?;

            // 读取压缩的客户端公钥 (33字节)
            let mut compressed_pub_key = [0u8; 33];
            read_safely(&mut self.input, 33, &mut compressed_pub_key)?;

            self.position += 16 + 33;

            // 读取日志长度
            let log_length = read_u16_le(&mut self.input)? as usize;
            // info!("日志长度: {}", log_length);

            if log_length == 0 || log_length > SINGLE_LOG_CONTENT_MAX_LENGTH {
                eprintln!("无效的日志长度: {}", log_length);
                std::io::stderr().flush().unwrap();
                return Ok(ReadResult::NeedRecover(-4));
            }

            self.position += 2 + log_length as u64;

            // 读取加密的日志数据
            let mut buf = vec![0u8; log_length];
            read_safely(&mut self.input, log_length, &mut buf)?;

            // 解密数据（直接使用压缩公钥）
            let plain = match self.decrypt(&compressed_pub_key, &iv, &buf) {
                Ok(p) => p,
                Err(_) => {
                    eprintln!("解密失败");
                    std::io::stderr().flush().unwrap();
                    return Ok(ReadResult::NeedRecover(-5));
                }
            };

            // 根据压缩模式处理数据
            match compress_mode {
                CompressMode::Zlib => self.inflater.decompress(&plain, out_buf)?,
                CompressMode::None => {
                    let copy_len = plain.len().min(out_buf.len());
                    out_buf[..copy_len].copy_from_slice(&plain[..copy_len]);
                    copy_len
                }
            }
        } else {
            // 非加密模式
            let log_length = read_u16_le(&mut self.input)? as usize;

            if log_length == 0 || log_length > SINGLE_LOG_CONTENT_MAX_LENGTH {
                eprintln!("无效的日志长度: {}", log_length);
                std::io::stderr().flush().unwrap();
                return Ok(ReadResult::NeedRecover(-6));
            }

            self.position += 2 + log_length as u64;

            // 读取日志数据
            let mut buf = vec![0u8; log_length];
            read_safely(&mut self.input, log_length, &mut buf)?;

            // 根据压缩模式处理数据
            match compress_mode {
                CompressMode::Zlib => self.inflater.decompress(&buf, out_buf)?,
                CompressMode::None => {
                    let copy_len = log_length.min(out_buf.len());
                    out_buf[..copy_len].copy_from_slice(&buf[..copy_len]);
                    copy_len
                }
            }
        };

        // 读取并验证同步标记
        let mut sync_marker = [0u8; 8];
        read_safely(&mut self.input, 8, &mut sync_marker)?;

        if sync_marker != SYNC_MARKER {
            eprintln!("同步标记不匹配");
            std::io::stderr().flush().unwrap();
            return Ok(ReadResult::NeedRecover(-7));
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

/// 准备服务器私钥
///
/// 将十六进制字符串格式的私钥转换为 EC 私钥
///
/// # Arguments
/// * `svr_pri_key` - 十六进制格式的私钥字符串
///
/// # Returns
/// 返回 SecretKey
fn prepare_svr_pri_key(svr_pri_key: &str) -> Result<SecretKey> {
    // 将十六进制字符串转换为字节数组
    let key_bytes = hex::decode(svr_pri_key)?;
    
    // 创建 SecretKey
    SecretKey::from_slice(&key_bytes)
        .map_err(|e| GlogError::EllipticCurveError(format!("无效的私钥: {}", e)))
}

/// 准备客户端公钥
///
/// 将64字节的原始公钥数据转换为 EC 公钥
///
/// # Arguments
/// * `client_pub_key` - 64字节的公钥数据（X和Y坐标各32字节）
///
/// # Returns
/// 返回 PublicKey
fn prepare_client_pub_key(client_pub_key: &[u8]) -> Result<PublicKey> {
    if client_pub_key.len() != 64 {
        return Err(GlogError::PublicKeyDecompressError(
            format!("公钥长度错误: 期望64字节，实际{}字节", client_pub_key.len())
        ));
    }

    // 构造未压缩格式的公钥（0x04 + X + Y）
    let mut uncompressed = vec![0x04u8];
    uncompressed.extend_from_slice(client_pub_key);

    // 解析公钥
    let encoded_point = k256::EncodedPoint::from_bytes(&uncompressed)
        .map_err(|e| GlogError::PublicKeyDecompressError(format!("编码点解析失败: {}", e)))?;
    
    let pub_key = PublicKey::from_encoded_point(&encoded_point);
    
    if pub_key.is_some().into() {
        Ok(pub_key.unwrap())
    } else {
        Err(GlogError::PublicKeyDecompressError("无效的公钥点".to_string()))
    }
}

/// 解压缩公钥
///
/// 将压缩格式的 secp256k1 公钥解压为未压缩格式
///
/// # Arguments
/// * `compressed_key` - 33字节的压缩公钥
///
/// # Returns
/// 返回64字节的未压缩公钥（不含0x04前缀）
pub fn decompress_public_key(compressed_key: &[u8]) -> Result<Vec<u8>> {
    if compressed_key.len() != 33 {
        return Err(GlogError::PublicKeyDecompressError(
            format!("压缩公钥长度错误: 期望33字节，实际{}字节", compressed_key.len())
        ));
    }

    // 解析压缩格式的公钥
    let encoded_point = k256::EncodedPoint::from_bytes(compressed_key)
        .map_err(|e| GlogError::PublicKeyDecompressError(format!("编码点解析失败: {}", e)))?;

    // 将公钥转换为未压缩格式
    let pub_key = PublicKey::from_encoded_point(&encoded_point);
    
    if pub_key.is_none().into() {
        return Err(GlogError::PublicKeyDecompressError("无效的压缩公钥".to_string()));
    }

    let pub_key = pub_key.unwrap();
    let uncompressed = pub_key.to_encoded_point(false);
    let bytes = uncompressed.as_bytes();

    // 返回不含 0x04 前缀的64字节
    if bytes.len() == 65 && bytes[0] == 0x04 {
        Ok(bytes[1..].to_vec())
    } else {
        Err(GlogError::PublicKeyDecompressError(
            format!("未压缩公钥格式错误: 长度={}", bytes.len())
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prepare_svr_pri_key() {
        // 测试有效的私钥
        let key = "1C74B66FCB1C54FD4386173CFAF3BC53C8DF6B89F799DE1A1E7CEBBC43CBFD38";
        let result = prepare_svr_pri_key(key);
        assert!(result.is_ok());
    }

    #[test]
    fn test_decompress_public_key_invalid_length() {
        let invalid_key = vec![0u8; 32]; // 错误的长度
        let result = decompress_public_key(&invalid_key);
        assert!(result.is_err());
    }
}
