//! # 日志消息定义模块
//!
//! 本模块定义了与 Protobuf Log.proto 对应的 Rust 结构体。
//! 由于 proto 文件比较简单，我们手动实现而不使用 prost-build。

use prost::Message;

/// 日志级别枚举
///
/// 对应 proto 文件中的 Log.Level 枚举
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(i32)]
pub enum Level {
    /// 信息级别
    Info = 0,
    /// 调试级别
    Debug = 1,
    /// 详细级别
    Verbose = 2,
    /// 警告级别
    Warn = 3,
    /// 错误级别
    Error = 4,
}

impl Level {
    /// 从 i32 值创建 Level
    ///
    /// # Arguments
    /// * `value` - 整数值
    ///
    /// # Returns
    /// 返回对应的 Level，如果值无效则返回 Info
    pub fn from_i32(value: i32) -> Self {
        match value {
            0 => Level::Info,
            1 => Level::Debug,
            2 => Level::Verbose,
            3 => Level::Warn,
            4 => Level::Error,
            _ => Level::Info,
        }
    }

    /// 获取日志级别的字符串表示
    ///
    /// # Returns
    /// 返回级别的中文名称
    pub fn as_str(&self) -> &'static str {
        match self {
            Level::Info => "Info",
            Level::Debug => "Debug",
            Level::Verbose => "Verbose",
            Level::Warn => "Warn",
            Level::Error => "Error",
        }
    }
}

impl Default for Level {
    fn default() -> Self {
        Level::Info
    }
}

impl From<i32> for Level {
    fn from(value: i32) -> Self {
        Level::from_i32(value)
    }
}

/// 日志消息结构体
///
/// 对应 proto 文件中的 Log message
#[derive(Clone, PartialEq, Message)]
pub struct Log {
    /// 日志类型
    #[prost(int32, tag = "1")]
    pub log_type: i32,
    
    /// 时间戳（毫秒级 Unix 时间戳的字符串表示）
    #[prost(string, tag = "2")]
    pub timestamp: String,
    
    /// 日志级别
    #[prost(enumeration = "Level", tag = "3")]
    pub log_level: i32,
    
    /// 进程 ID
    #[prost(int32, tag = "4")]
    pub pid: i32,
    
    /// 线程 ID
    #[prost(string, tag = "5")]
    pub tid: String,
    
    /// 日志标签
    #[prost(string, tag = "6")]
    pub tag: String,
    
    /// 日志消息内容
    #[prost(string, tag = "7")]
    pub msg: String,
}

impl Log {
    /// 创建新的日志实例
    pub fn new() -> Self {
        Self::default()
    }

    /// 从字节数组解码日志
    ///
    /// # Arguments
    /// * `buf` - 包含 protobuf 编码数据的字节切片
    ///
    /// # Returns
    /// 成功返回 Log 实例，失败返回解码错误
    pub fn decode_from(buf: &[u8]) -> Result<Self, prost::DecodeError> {
        Log::decode(buf)
    }

    /// 获取日志级别枚举
    pub fn level(&self) -> Level {
        Level::from_i32(self.log_level)
    }

    /// 获取格式化的时间戳
    ///
    /// # Returns
    /// 返回格式化的日期时间字符串 (yyyy-MM-dd HH:mm:ss.SSS)
    pub fn formatted_timestamp(&self) -> String {
        use chrono::{DateTime, TimeZone, Local};
        
        if let Ok(ts) = self.timestamp.parse::<i64>() {
            // 将毫秒时间戳转换为 DateTime
            if let Some(dt) = DateTime::from_timestamp_millis(ts) {
                // 转换为本地时间
                let local_dt = Local.from_utc_datetime(&dt.naive_utc());
                return local_dt.format("%Y-%m-%d %H:%M:%S%.3f").to_string();
            }
        }
        
        // 如果解析失败，返回原始时间戳
        self.timestamp.clone()
    }

    /// 格式化为日志字符串
    ///
    /// 生成类似 Java 版本的日志输出格式
    ///
    /// # Returns
    /// 返回格式化的日志字符串
    pub fn format(&self) -> String {
        format!(
            "{} [{}] [{}] {{{}:{}}} {}",
            self.formatted_timestamp(),
            self.level().as_str(),
            self.tag,
            self.pid,
            self.tid,
            self.msg
        )
    }
}

// Default 已由 Message derive 宏自动实现

impl std::fmt::Display for Log {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.format())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_level_from_i32() {
        assert_eq!(Level::from_i32(0), Level::Info);
        assert_eq!(Level::from_i32(1), Level::Debug);
        assert_eq!(Level::from_i32(2), Level::Verbose);
        assert_eq!(Level::from_i32(3), Level::Warn);
        assert_eq!(Level::from_i32(4), Level::Error);
        assert_eq!(Level::from_i32(99), Level::Info); // 未知值默认为 Info
    }

    #[test]
    fn test_level_as_str() {
        assert_eq!(Level::Info.as_str(), "Info");
        assert_eq!(Level::Error.as_str(), "Error");
    }

    #[test]
    fn test_log_default() {
        let log = Log::new();
        assert_eq!(log.log_type, 0);
        assert_eq!(log.timestamp, "");
        assert_eq!(log.log_level, 0);
    }

    #[test]
    fn test_log_format() {
        let log = Log {
            log_type: 1,
            timestamp: "1700000000000".to_string(), // 2023-11-14
            log_level: 0,
            pid: 1234,
            tid: "5678".to_string(),
            tag: "TestTag".to_string(),
            msg: "Test message".to_string(),
        };
        
        let formatted = log.format();
        assert!(formatted.contains("[Info]"));
        assert!(formatted.contains("[TestTag]"));
        assert!(formatted.contains("{1234:5678}"));
        assert!(formatted.contains("Test message"));
    }
}
