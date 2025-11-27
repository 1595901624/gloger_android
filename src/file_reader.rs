use crate::error::{ClogError, Result};
use crate::glog_reader::SYNC_MARKER;
use aes::cipher::KeyIvInit;
use byteorder::{LittleEndian, ReadBytesExt};
use cfb_mode::cipher::AsyncStreamCipher;
use elliptic_curve::sec1::FromEncodedPoint;
use flate2::read::ZlibDecoder;
use k256::{elliptic_curve::sec1::ToEncodedPoint, AffinePoint, EncodedPoint, PublicKey, SecretKey};
use log::info;
use std::io::{BufReader, Cursor, Read};

/// AES-128-CFB 解密器类型别名
type Aes128CfbDec = cfb_mode::Decryptor<aes::Aes128>;

/// 单条日志最大长度
const MAX_LOG_LENGTH: usize = 16384;

/// 文件读取器 trait
pub trait FileReader {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize>;
}

/// 压缩模式
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CompressMode {
    None,
    Zlib,
}

/// 加密模式
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EncryptMode {
    None,
    Aes,
}

// ============================================================================
// FileReaderV3 - V3 版本格式（仅压缩，无加密）
// ============================================================================

pub struct FileReaderV3<R: Read> {
    reader: BufReader<R>,
    compress_mode: CompressMode,
    #[allow(dead_code)]
    encrypt_mode: EncryptMode,
}

impl<R: Read> FileReaderV3<R> {
    pub fn new(reader: BufReader<R>) -> Result<Self> {
        Ok(Self {
            reader,
            compress_mode: CompressMode::None,
            encrypt_mode: EncryptMode::None,
        })
    }

    pub fn read_header(&mut self) -> Result<()> {
        // 读取模式字节
        let mut mode_byte = [0u8; 1];
        self.reader.read_exact(&mut mode_byte)?;
        let mode = mode_byte[0];

        // 解析压缩模式（高4位）
        self.compress_mode = match mode >> 4 {
            0 => CompressMode::None,
            1 => CompressMode::Zlib,
            v => return Err(ClogError::InvalidCompressMode(v)),
        };

        // 解析加密模式（低4位）
        self.encrypt_mode = match mode & 0x0F {
            0 => EncryptMode::None,
            1 => EncryptMode::Aes,
            v => return Err(ClogError::InvalidEncryptMode(v)),
        };

        info!(
            "V3 Header - 压缩模式: {:?}, 加密模式: {:?}",
            self.compress_mode, self.encrypt_mode
        );

        // 读取 proto 名称长度
        let proto_name_len = self.reader.read_u16::<LittleEndian>()? as usize;

        // 读取 proto 名称
        let mut proto_name = vec![0u8; proto_name_len];
        self.reader.read_exact(&mut proto_name)?;
        let proto_name_str = String::from_utf8_lossy(&proto_name);
        info!("Proto 名称: {}", proto_name_str);

        // 读取并验证同步标记
        let mut sync_marker = [0u8; 8];
        self.reader.read_exact(&mut sync_marker)?;
        if sync_marker != SYNC_MARKER {
            return Err(ClogError::SyncMarkerMismatch);
        }

        Ok(())
    }
}

impl<R: Read> FileReader for FileReaderV3<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        // 读取日志长度
        let log_length = match self.reader.read_u16::<LittleEndian>() {
            Ok(len) => len as usize,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(0),
            Err(e) => return Err(e.into()),
        };

        if log_length == 0 || log_length > MAX_LOG_LENGTH {
            return Err(ClogError::InvalidLogLength(log_length));
        }

        // 读取压缩数据
        let mut compressed = vec![0u8; log_length];
        self.reader.read_exact(&mut compressed)?;

        // 根据需要解压缩
        let decompressed_len = if self.compress_mode == CompressMode::Zlib {
            decompress(&compressed, buf)?
        } else {
            buf[..log_length].copy_from_slice(&compressed);
            log_length
        };

        // 读取并验证同步标记
        let mut sync_marker = [0u8; 8];
        self.reader.read_exact(&mut sync_marker)?;
        if sync_marker != SYNC_MARKER {
            return Err(ClogError::SyncMarkerMismatch);
        }

        Ok(decompressed_len)
    }
}

// ============================================================================
// FileReaderV4 - V4 版本格式（加密 + 压缩）
// ============================================================================

pub struct FileReaderV4<R: Read> {
    reader: BufReader<R>,
    server_secret_key: Option<SecretKey>,
}

impl<R: Read> FileReaderV4<R> {
    pub fn new(reader: BufReader<R>, key: Option<&str>) -> Result<Self> {
        let server_secret_key = key.and_then(|k| parse_private_key(k).ok());

        Ok(Self {
            reader,
            server_secret_key,
        })
    }

    pub fn read_header(&mut self) -> Result<()> {
        // 读取 proto 名称长度
        let proto_name_len = self.reader.read_u16::<LittleEndian>()? as usize;

        // 读取 proto 名称
        let mut proto_name = vec![0u8; proto_name_len];
        self.reader.read_exact(&mut proto_name)?;
        let proto_name_str = String::from_utf8_lossy(&proto_name);
        info!("V4 Proto 名称: {}", proto_name_str);

        // 读取并验证同步标记
        let mut sync_marker = [0u8; 8];
        self.reader.read_exact(&mut sync_marker)?;
        if sync_marker != SYNC_MARKER {
            return Err(ClogError::SyncMarkerMismatch);
        }

        Ok(())
    }

    /// 使用 ECDH + AES-CFB 解密数据
    ///
    /// # 参数
    /// - client_pub_key: 客户端公钥（64字节，无前缀的未压缩格式）
    /// - iv: AES 初始化向量（16字节）
    /// - encrypted: 加密数据
    fn decrypt(&self, client_pub_key: &[u8], iv: &[u8], encrypted: &[u8]) -> Result<Vec<u8>> {
        let server_key = self
            .server_secret_key
            .as_ref()
            .ok_or(ClogError::CipherNotReady)?;

        // 解析客户端公钥（64字节未压缩格式，无前缀）
        // 需要添加 0x04 前缀表示未压缩点
        let mut full_key = vec![0x04];
        full_key.extend_from_slice(client_pub_key);

        let encoded_point =
            EncodedPoint::from_bytes(&full_key).map_err(|_| ClogError::DecryptionFailed)?;

        let client_public_key = PublicKey::from_encoded_point(&encoded_point);
        if client_public_key.is_none().into() {
            return Err(ClogError::DecryptionFailed);
        }
        let client_public_key = client_public_key.unwrap();

        // ECDH 密钥协商
        let shared_secret = elliptic_curve::ecdh::diffie_hellman(
            server_key.to_nonzero_scalar(),
            client_public_key.as_affine(),
        );

        // 使用共享密钥的前16字节作为 AES 密钥
        let shared_bytes = shared_secret.raw_secret_bytes();
        let aes_key: [u8; 16] = shared_bytes[..16].try_into().unwrap();
        let iv_array: [u8; 16] = iv.try_into().map_err(|_| ClogError::DecryptionFailed)?;

        // AES-CFB-128 解密
        // Java 使用 AES/CFB/NoPadding，CFB 是流密码模式，无需填充
        let mut decrypted = encrypted.to_vec();
        let decryptor = Aes128CfbDec::new(&aes_key.into(), &iv_array.into());
        decryptor.decrypt(&mut decrypted);

        Ok(decrypted)
    }
}

impl<R: Read> FileReader for FileReaderV4<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        // 读取模式字节
        let mode = match self.reader.read_u8() {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(0),
            Err(e) => return Err(e.into()),
        };

        // 解析压缩模式（高4位）
        // V4 格式: 1=无压缩, 2=Zlib
        let compress_mode = match mode >> 4 {
            1 => CompressMode::None,
            2 => CompressMode::Zlib,
            v => return Err(ClogError::InvalidCompressMode(v)),
        };

        // 解析加密模式（低4位）
        // V4 格式: 1=无加密, 2=AES
        let encrypt_mode = match mode & 0x0F {
            1 => EncryptMode::None,
            2 => EncryptMode::Aes,
            v => return Err(ClogError::InvalidEncryptMode(v)),
        };

        info!(
            "V4 日志 - 压缩模式: {:?}, 加密模式: {:?}",
            compress_mode, encrypt_mode
        );

        let log_length: usize;

        if encrypt_mode == EncryptMode::Aes {
            if self.server_secret_key.is_none() {
                return Err(ClogError::CipherNotReady);
            }

            // 读取 IV（16字节）
            let mut iv = [0u8; 16];
            self.reader.read_exact(&mut iv)?;

            // 读取压缩公钥（33字节）
            let mut compressed_pub_key = [0u8; 33];
            self.reader.read_exact(&mut compressed_pub_key)?;

            // 解压缩公钥（33字节 -> 64字节）
            let client_pub_key = decompress_public_key(&compressed_pub_key)?;

            // 读取加密日志长度
            let encrypted_len = self.reader.read_u16::<LittleEndian>()? as usize;
            if encrypted_len == 0 || encrypted_len > MAX_LOG_LENGTH {
                return Err(ClogError::InvalidLogLength(encrypted_len));
            }

            // 读取加密数据
            let mut encrypted = vec![0u8; encrypted_len];
            self.reader.read_exact(&mut encrypted)?;

            // 解密
            let decrypted = self.decrypt(&client_pub_key, &iv, &encrypted)?;

            // 根据需要解压缩
            log_length = if compress_mode == CompressMode::Zlib {
                decompress(&decrypted, buf)?
            } else {
                buf[..decrypted.len()].copy_from_slice(&decrypted);
                decrypted.len()
            };
        } else {
            // 无加密模式
            let len = self.reader.read_u16::<LittleEndian>()? as usize;
            if len == 0 || len > MAX_LOG_LENGTH {
                return Err(ClogError::InvalidLogLength(len));
            }

            let mut data = vec![0u8; len];
            self.reader.read_exact(&mut data)?;

            // 根据需要解压缩
            log_length = if compress_mode == CompressMode::Zlib {
                decompress(&data, buf)?
            } else {
                buf[..len].copy_from_slice(&data);
                len
            };
        }

        // 读取并验证同步标记
        let mut sync_marker = [0u8; 8];
        self.reader.read_exact(&mut sync_marker)?;
        if sync_marker != SYNC_MARKER {
            return Err(ClogError::SyncMarkerMismatch);
        }

        Ok(log_length)
    }
}

// ============================================================================
// 辅助函数
// ============================================================================

/// 将十六进制字符串解析为 secp256k1 私钥
fn parse_private_key(hex_str: &str) -> Result<SecretKey> {
    let bytes = hex::decode(hex_str).map_err(|_| ClogError::CipherNotReady)?;
    SecretKey::from_slice(&bytes).map_err(|_| ClogError::CipherNotReady)
}

/// 解压缩 secp256k1 压缩公钥（33字节）为未压缩格式（64字节）
fn decompress_public_key(compressed: &[u8]) -> Result<Vec<u8>> {
    let encoded_point =
        EncodedPoint::from_bytes(compressed).map_err(|_| ClogError::DecryptionFailed)?;

    let affine_point = AffinePoint::from_encoded_point(&encoded_point);
    if affine_point.is_none().into() {
        return Err(ClogError::DecryptionFailed);
    }
    let affine_point = affine_point.unwrap();

    // 获取未压缩编码（65字节，带 0x04 前缀）
    let uncompressed = affine_point.to_encoded_point(false);
    let bytes = uncompressed.as_bytes();

    // 返回64字节（去掉 0x04 前缀）
    Ok(bytes[1..].to_vec())
}

/// 解压缩 zlib 数据
fn decompress(input: &[u8], output: &mut [u8]) -> Result<usize> {
    let mut decoder = ZlibDecoder::new(Cursor::new(input));
    let len = decoder
        .read(output)
        .map_err(|e| ClogError::DecompressionFailed(e.to_string()))?;
    Ok(len)
}
