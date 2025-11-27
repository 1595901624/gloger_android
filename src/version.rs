//! # Glog 版本常量模块
//!
//! 本模块定义了 Glog 文件格式的版本号常量。
//! 不同版本的 Glog 文件具有不同的格式和特性。

/// Glog 初始版本
/// 
/// @deprecated 已废弃的初始版本
#[allow(dead_code)]
pub const GLOG_INITIAL_VERSION: u8 = 0x01;

/// Glog 修复位置版本
/// 
/// @deprecated 修复了错误的初始写入位置问题
#[allow(dead_code)]
pub const GLOG_FIX_POSITION_VERSION: u8 = 0x02;

/// Glog 恢复版本 (V3)
/// 
/// 在每条日志中添加同步标记，支持从损坏的文件中恢复数据
pub const GLOG_RECOVERY_VERSION: u8 = 0x03;

/// Glog 加密版本 (V4)
/// 
/// 在每条日志中存储 IV 和公钥，支持 AES CFB-128 加密
pub const GLOG_CIPHER_VERSION: u8 = 0x04;
