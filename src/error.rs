//! # 错误处理模块
//!
//! 本模块定义了 clog-reader 库中使用的所有错误类型。
//! 使用 `thiserror` 库来简化错误定义和实现。

use thiserror::Error;

/// Glog 读取器错误类型
///
/// 定义了读取和解析 Glog 文件时可能遇到的各种错误情况
#[derive(Error, Debug)]
pub enum GlogError {
    /// 文件损坏错误
    /// 当文件格式不正确或数据损坏时返回此错误
    #[error("文件损坏: {0}")]
    FileCorrupt(String),

    /// IO 错误
    /// 封装标准库的 IO 错误
    #[error("IO 错误: {0}")]
    Io(#[from] std::io::Error),

    /// 文件结束错误
    /// 当读取到文件末尾但期望更多数据时返回此错误
    #[error("意外的文件结束: 期望 {expected} 字节，但只有 {available} 字节可用")]
    UnexpectedEof {
        /// 期望读取的字节数
        expected: usize,
        /// 实际可用的字节数
        available: usize,
    },

    /// 魔数不匹配错误
    /// 当文件头的魔数与预期不符时返回此错误
    #[error("魔数不匹配")]
    MagicMismatch,

    /// 版本不支持错误
    /// 当文件版本不被支持时返回此错误
    #[error("不支持的版本: {0}")]
    UnsupportedVersion(u8),

    /// 同步标记不匹配错误
    /// 当日志条目的同步标记与预期不符时返回此错误
    #[error("同步标记不匹配")]
    SyncMarkerMismatch,

    /// 非法压缩模式错误
    /// 当遇到未知的压缩模式时返回此错误
    #[error("非法压缩模式: {0}")]
    IllegalCompressMode(u8),

    /// 非法加密模式错误
    /// 当遇到未知的加密模式时返回此错误
    #[error("非法加密模式: {0}")]
    IllegalEncryptMode(u8),

    /// 解压缩错误
    /// 当 zlib 解压缩失败时返回此错误
    #[error("解压缩失败: {0}")]
    DecompressError(String),

    /// 解密错误
    /// 当 AES 解密失败时返回此错误
    #[error("解密失败: {0}")]
    DecryptError(String),

    /// 加密密钥未设置错误
    /// 当需要解密但未提供密钥时返回此错误
    #[error("加密密钥未设置")]
    CipherNotReady,

    /// 日志长度无效错误
    /// 当日志长度超出有效范围时返回此错误
    #[error("无效的日志长度: {0}")]
    InvalidLogLength(usize),

    /// 公钥解压错误
    /// 当解压椭圆曲线公钥失败时返回此错误
    #[error("公钥解压失败: {0}")]
    PublicKeyDecompressError(String),

    /// Protobuf 解析错误
    /// 当解析 protobuf 消息失败时返回此错误
    #[error("Protobuf 解析错误: {0}")]
    ProtobufError(#[from] prost::DecodeError),

    /// ZIP 解压错误
    /// 当解压 ZIP 文件失败时返回此错误
    #[error("ZIP 解压错误: {0}")]
    ZipError(#[from] zip::result::ZipError),

    /// 十六进制解析错误
    /// 当解析十六进制字符串失败时返回此错误
    #[error("十六进制解析错误: {0}")]
    HexError(#[from] hex::FromHexError),

    /// 椭圆曲线错误
    /// 当椭圆曲线操作失败时返回此错误
    #[error("椭圆曲线错误: {0}")]
    EllipticCurveError(String),
}

/// 结果类型别名
/// 使用 GlogError 作为错误类型的 Result
pub type Result<T> = std::result::Result<T, GlogError>;

/// 读取结果枚举
///
/// 用于表示单条日志读取的结果状态
#[derive(Debug)]
pub enum ReadResult {
    /// 成功读取日志，包含读取的字节数
    Success(usize),
    /// 已到达文件末尾
    Eof,
    /// 需要恢复（遇到可恢复的错误）
    NeedRecover(i32),
}
