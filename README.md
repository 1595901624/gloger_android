# CLog Reader (Rust 版本)

一个用于读取和解析 Glog 格式日志文件的 Rust 工具库。

## 功能特性

- ✅ 支持 Glog V3（恢复版本）文件格式
- ✅ 支持 Glog V4（加密版本）文件格式
- ✅ 支持 zlib 压缩的日志数据解压
- ✅ 支持 AES-128-CFB 加密的日志数据解密
- ✅ 使用 secp256k1 椭圆曲线进行 ECDH 密钥交换
- ✅ 支持 Protobuf 格式的日志消息解析
- ✅ 支持从 ZIP 压缩包中提取日志文件

## 安装

确保已安装 Rust 工具链（推荐使用 rustup）：

```bash
# 安装 Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

## 编译

```bash
cd clog-reader
cargo build --release
```

编译后的可执行文件位于 `target/release/clog-reader`。

## 使用方法

### 命令行工具

```bash
# 显示版本信息
clog-reader --version

# 基本用法：解析日志 ZIP 文件
clog-reader -i <日志.zip>

# 按日志类型过滤
clog-reader -i <日志.zip> -t 0,1,2

# 指定输出文件
clog-reader -i <日志.zip> -o output.txt

# 显示帮助信息
clog-reader -h
```

### 作为库使用

在您的 `Cargo.toml` 中添加依赖：

```toml
[dependencies]
clog-reader = { path = "../clog-reader" }
```

示例代码：

```rust
use clog_reader::{glog, proto::Log, error::ReadResult};

fn main() -> anyhow::Result<()> {
    // 打开日志文件（带解密密钥）
    let mut reader = glog::open_with_key(
        "path/to/logfile.glog",
        Some("your_private_key_hex".to_string())
    )?;

    // 读取日志
    let mut buf = vec![0u8; glog::GlogReader::single_log_max_length()];
    
    loop {
        match reader.read(&mut buf)? {
            ReadResult::Success(len) => {
                // 解析 protobuf 日志
                let log = Log::decode_from(&buf[..len])?;
                println!("{}", log.format());
            }
            ReadResult::Eof => break,
            ReadResult::NeedRecover(code) => {
                eprintln!("需要恢复，错误码: {}", code);
                continue;
            }
        }
    }

    Ok(())
}
```

## 项目结构

```
clog-reader/
├── Cargo.toml          # 项目配置和依赖
├── src/
│   ├── lib.rs          # 库入口
│   ├── main.rs         # 命令行工具入口
│   ├── error.rs        # 错误类型定义
│   ├── version.rs      # 版本常量
│   ├── glog.rs         # 主读取器接口
│   ├── proto.rs        # Protobuf 日志消息定义
│   └── reader/
│       ├── mod.rs      # 读取器模块入口
│       ├── v3.rs       # V3 版本读取器
│       └── v4.rs       # V4 版本读取器（支持加密）
└── README.md
```

## Glog 文件格式说明

### V3 格式 (恢复版本)

```
+------------------------------------------------------------------+
|                         magic number (4)                         |
+----------------+----------------+--------------------------------+
|   version (1)  |  mode set (1)  |     proto name length (2)      |
+----------------+----------------+--------------------------------+
|       proto name (0...)       ...
+------------------------------------------------------------------+
|       sync marker (8)     ...                                    |
+------------------------------------------------------------------+
|         log length (2)          |
+---------------------------------+--------------------------------+
|                           log data (0...)         ...
+------------------------------------------------------------------+
|       sync marker (8)     ...                                    |
+------------------------------------------------------------------+
```

### V4 格式 (加密版本)

```
+------------------------------------------------------------------+
|                         magic number (4)                         |
+----------------+--------------------------------+-----------------+
|   version (1)  |     proto name length (2)     |
+----------------+--------------------------------+-----------------+
|       proto name (0...)       ...
+------------------------------------------------------------------+
|       sync marker (8)     ...                                    |
+------------------------------------------------------------------+
|  mode set (1)  |          optional: AES random iv (16)
+----------------+-------------------------------------------------+
|       optional: client ecc public key (33, compressed)
+------------------------------------------------------------------+
|        log length (2)         |
+-------------------------------+----------------------------------+
|                           log data (0...)         ...
+------------------------------------------------------------------+
|       sync marker (8)     ...                                    |
+------------------------------------------------------------------+
```

## 依赖库

- `clap` - 命令行参数解析
- `thiserror` / `anyhow` - 错误处理
- `flate2` - zlib 解压缩
- `aes` / `cfb-mode` - AES-CFB 加密
- `k256` - secp256k1 椭圆曲线 ECDH
- `prost` - Protobuf 支持
- `chrono` - 日期时间处理
- `walkdir` - 文件遍历
- `zip` - ZIP 解压缩

## 许可证

MIT License
