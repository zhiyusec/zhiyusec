# Config 配置管理模块

## 功能说明

本模块负责应用程序的配置管理，使用 Viper 库提供灵活的配置加载方式。

## 主要特性

- 支持多种配置文件格式：YAML、JSON、TOML
- 支持环境变量覆盖配置
- 支持命令行参数覆盖
- 提供默认配置值
- 配置验证功能

## 配置结构

### ScanConfig - 扫描配置
- `paths`: 扫描路径列表
- `max_file_size`: 最大文件大小限制（字节）
- `scan_archives`: 是否扫描压缩包
- `follow_symlinks`: 是否跟随符号链接
- `blacklist`: 黑名单路径（正则表达式）
- `whitelist`: 白名单路径（正则表达式）
- `checkpoint_file`: 断点续扫文件路径
- `enable_checkpoint`: 是否启用断点续扫

### DetectConfig - 检测配置
- `rule_files`: 规则文件路径列表
- `enable_builtin_rules`: 是否启用内置规则
- `entropy_threshold`: 熵值阈值（默认4.5）
- `enable_entropy_check`: 是否启用熵值检测
- `enable_crypto_check`: 是否启用加密检测
- `custom_keywords`: 自定义关键词列表
- `enabled_types`: 启用的敏感信息类型

### ReportConfig - 报告配置
- `formats`: 输出格式（json/sarif/csv/html）
- `output_dir`: 输出目录
- `file_prefix`: 文件名前缀
- `include_large_files`: 是否包含超大文件列表
- `min_severity`: 最小严重性级别
- `verbose`: 是否显示详细信息

### PerformanceConfig - 性能配置
- `max_concurrency`: 最大并发数
- `buffer_size`: 文件读取缓冲区大小
- `scan_timeout`: 扫描超时时间
- `show_progress`: 是否显示进度条

## 使用示例

```go
import "github.com/zhiyusec/zhiyusec-leaks/pkg/config"

// 加载配置
cfg, err := config.LoadConfig("configs/zhiyusec.yaml")
if err != nil {
    log.Fatal(err)
}

// 使用配置
for _, path := range cfg.Scan.Paths {
    // 扫描路径
}
```

## 配置文件搜索路径

1. 指定的配置文件路径
2. 当前目录
3. `./configs` 目录
4. `$HOME/.zhiyusec` 目录
5. `/etc/zhiyusec` 目录

## 环境变量

环境变量以 `ZHIYUSEC_` 为前缀，例如：
- `ZHIYUSEC_SCAN_PATHS`
- `ZHIYUSEC_PERFORMANCE_MAX_CONCURRENCY`
