/// 手动实现的 Protobuf Log 消息结构
pub mod clog {
    use prost::Message;

    /// 日志级别枚举
    #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
    #[repr(i32)]
    pub enum Level {
        #[default]
        Info = 0,
        Debug = 1,
        Verbose = 2,
        Warn = 3,
        Error = 4,
    }

    impl std::fmt::Debug for Level {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::Info => write!(f, "Info"),
                Self::Debug => write!(f, "Debug"),
                Self::Verbose => write!(f, "Verbose"),
                Self::Warn => write!(f, "Warn"),
                Self::Error => write!(f, "Error"),
            }
        }
    }

    impl Level {
        /// 从 i32 值转换为 Level 枚举
        pub fn from_i32(value: i32) -> Option<Self> {
            match value {
                0 => Some(Self::Info),
                1 => Some(Self::Debug),
                2 => Some(Self::Verbose),
                3 => Some(Self::Warn),
                4 => Some(Self::Error),
                _ => None,
            }
        }
    }

    /// 日志条目消息
    #[derive(Clone, PartialEq, Message)]
    pub struct Log {
        /// 日志类型
        #[prost(int32, tag = "1")]
        pub r#type: i32,
        /// 时间戳（毫秒）
        #[prost(string, tag = "2")]
        pub timestamp: String,
        /// 日志级别
        #[prost(int32, tag = "3")]
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
        /// 创建新的 Log 实例
        pub fn new(
            r#type: i32,
            timestamp: String,
            log_level: Level,
            pid: i32,
            tid: String,
            tag: String,
            msg: String,
        ) -> Self {
            Self {
                r#type,
                timestamp,
                log_level: log_level as i32,
                pid,
                tid,
                tag,
                msg,
            }
        }
    }
}
