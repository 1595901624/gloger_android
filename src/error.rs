use thiserror::Error;

/// CLog 读取器自定义错误类型
#[derive(Error, Debug)]
pub enum ClogError {
    #[error("文件损坏: {0}")]
    FileCorrupt(String),

    #[error("魔数不匹配")]
    MagicMismatch,

    #[error("版本号不匹配: {0}")]
    VersionMismatch(u8),

    #[error("同步标记不匹配")]
    SyncMarkerMismatch,

    #[error("无效的压缩模式: {0}")]
    InvalidCompressMode(u8),

    #[error("无效的加密模式: {0}")]
    InvalidEncryptMode(u8),

    #[error("密钥未就绪")]
    CipherNotReady,

    #[error("解密失败")]
    DecryptionFailed,

    #[error("解压缩失败: {0}")]
    DecompressionFailed(String),

    #[error("无效的日志长度: {0}")]
    InvalidLogLength(usize),

    #[error("IO 错误: {0}")]
    Io(#[from] std::io::Error),

    #[error("已到达文件末尾")]
    Eof,
}

pub type Result<T> = std::result::Result<T, ClogError>;
