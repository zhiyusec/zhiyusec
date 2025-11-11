# zhiyusec-leaks 使用文档

## 📖 简介

**zhiyusec-leaks** 是知御安全实验室开发的企业级敏感信息泄漏检测工具，用于扫描文件系统中的敏感信息，包括：

- API 密钥和访问令牌
- 密码和凭证
- 私钥和证书
- 数据库连接字符串
- 个人身份信息（PII）
- 企业敏感信息

## ✨ 核心特性

- **多规则检测引擎** - 内置 30+ 检测规则，支持自定义规则
- **高性能并发扫描** - 可控并发度，支持大规模文件扫描
- **智能熵值分析** - 自动识别高熵随机字符串
- **多格式报告输出** - 支持 JSON、CSV、HTML、SARIF 格式
- **文件类型智能识别** - 自动跳过二进制、图片、视频等文件
- **归档文件处理** - 支持 ZIP、TAR 等压缩包扫描
- **黑白名单过滤** - 灵活配置扫描范围
- **实时进度显示** - 友好的命令行交互体验

## 🚀 快速开始

### 安装

#### 从源码构建

```bash
git clone https://github.com/zhiyusec/zhiyusec-leaks.git
cd zhiyusec-leaks
go build -o zhiyusec-leaks cmd/zhiyusec-leaks/main.go
```

#### 安装到系统

```bash
go install github.com/zhiyusec/zhiyusec-leaks/cmd/zhiyusec-leaks@latest
```

### 基本使用

#### 扫描当前目录

```bash
zhiyusec-leaks .
```

#### 扫描指定路径

```bash
zhiyusec-leaks /path/to/scan
```

#### 扫描多个路径

```bash
zhiyusec-leaks /path/1 /path/2 /path/3
```

## 📋 命令行参数

```bash
zhiyusec-leaks [flags] [paths...]

Flags:
  -c, --config string           配置文件路径
  -p, --paths strings           扫描路径列表
  -o, --output string           报告输出目录 (默认 "reports")
  -f, --format strings          报告格式 json,csv,html,sarif (默认 [json])
      --max-concurrency int     最大并发扫描数 (默认 10)
      --max-file-size int       最大文件大小(字节) (默认 104857600)
  -v, --verbose                 详细输出模式
      --no-progress             禁用进度条
  -h, --help                    帮助信息
      --version                 版本信息
```

## 🔧 配置文件

### 创建配置文件

在项目根目录或 `~/.zhiyusec/` 目录下创建 `zhiyusec.yaml`：

```yaml
scan:
  paths:
    - "."
  max_file_size: 104857600  # 100MB
  scan_archives: true
  follow_symlinks: false
  blacklist:
    - "node_modules"
    - "\\.git"
    - "vendor"

detect:
  enable_builtin_rules: true
  entropy_threshold: 4.5
  enable_entropy_check: true
  rule_files:
    - "configs/rules.yaml"

report:
  formats:
    - "json"
    - "html"
  output_dir: "reports"
  min_severity: "low"

performance:
  max_concurrency: 10
  show_progress: true
```

### 使用配置文件

```bash
zhiyusec-leaks -c zhiyusec.yaml
```

## 📊 使用示例

### 示例 1：扫描项目目录并生成 HTML 报告

```bash
zhiyusec-leaks -f html,json -o ./scan-results /path/to/project
```

### 示例 2：高并发扫描大型项目

```bash
zhiyusec-leaks --max-concurrency 20 --max-file-size 200000000 /large/project
```

### 示例 3：仅扫描高危问题

修改配置文件中的 `min_severity` 为 `high`：

```yaml
report:
  min_severity: "high"
```

### 示例 4：使用自定义规则

创建 `custom-rules.yaml`：

```yaml
version: "1.0.0"
rules:
  - id: "my-api-key"
    description: "检测自定义 API Key"
    type: "api_key"
    pattern: 'MY_API_[A-Z0-9]{32}'
    severity: "critical"
    enabled: true
```

在配置文件中引用：

```yaml
detect:
  rule_files:
    - "configs/rules.yaml"
    - "custom-rules.yaml"
```

## 📈 报告格式

### JSON 报告

包含完整的扫描结果和元数据：

```json
{
  "start_time": "2025-01-11T10:00:00Z",
  "end_time": "2025-01-11T10:05:00Z",
  "duration": 300000000000,
  "findings": [
    {
      "id": "20250111100100.000001",
      "rule_id": "aws-access-key",
      "description": "检测 AWS 访问密钥",
      "file_path": "/path/to/file.js",
      "line_number": 42,
      "severity": "critical",
      "confidence": 80
    }
  ]
}
```

### CSV 报告

适合导入 Excel 或其他数据分析工具：

```csv
ID,规则ID,描述,文件路径,行号,严重性,置信度
20250111100100.000001,aws-access-key,检测 AWS 访问密钥,/path/to/file.js,42,critical,80
```

### HTML 报告

美观的可视化报告，包含统计图表和详细信息。

### SARIF 报告

符合 SARIF 2.1.0 标准，可集成到 GitHub、GitLab 等平台。

## 🛡️ 检测规则

### 内置规则类型

- **API 密钥**: AWS、Azure、Google Cloud、GitHub、Slack 等
- **云服务**: 阿里云、腾讯云、华为云等
- **数据库**: MySQL、PostgreSQL、MongoDB、Redis 等
- **凭证**: 密码、Token、证书、私钥
- **PII**: 身份证、手机号、邮箱、银行卡等
- **企业信息**: 合同号、车牌号、VIN 码等

### 自定义规则

规则文件格式：

```yaml
version: "1.0.0"
rules:
  - id: "unique-rule-id"
    description: "规则描述"
    type: "api_key"
    pattern: '正则表达式'
    severity: "high"  # low, medium, high, critical
    tags: ["tag1", "tag2"]
    enabled: true
    entropy_threshold: 4.5  # 可选
    exclusions:  # 可选，排除误报
      - "test.*"
```

## 🔍 最佳实践

### 1. CI/CD 集成

在 GitHub Actions 中使用：

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Install zhiyusec-leaks
        run: go install github.com/zhiyusec/zhiyusec-leaks/cmd/zhiyusec-leaks@latest
      - name: Run scan
        run: zhiyusec-leaks -f sarif -o results .
      - name: Upload results
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results/zhiyusec-scan-*.sarif
```

### 2. 定期扫描

使用 cron 定期扫描 NAS 或文件服务器：

```bash
#!/bin/bash
# scan.sh
zhiyusec-leaks -c /etc/zhiyusec/config.yaml /mnt/nas
```

Crontab 配置：

```cron
0 2 * * * /path/to/scan.sh
```

### 3. 性能优化

- 使用黑名单排除不需要扫描的目录（node_modules、.git 等）
- 调整 `max_concurrency` 适配服务器性能
- 设置合理的 `max_file_size` 避免扫描超大文件

### 4. 减少误报

- 调整 `entropy_threshold` 过滤低熵字符串
- 在规则中添加 `exclusions` 排除特定模式
- 使用 `min_severity` 只关注高危问题

## 📦 项目结构

```
zhiyusec-leaks/
├── cmd/
│   └── zhiyusec-leaks/     # 命令行入口
├── pkg/
│   ├── config/             # 配置管理
│   ├── sources/            # 文件扫描
│   ├── detect/             # 检测引擎
│   ├── finding/            # 结果处理
│   ├── report/             # 报告生成
│   ├── runner/             # 主引擎
│   └── utils/              # 工具函数
├── internal/
│   ├── rules/              # 规则引擎
│   └── filetype/           # 文件类型检测
├── configs/
│   ├── zhiyusec.yaml       # 配置示例
│   └── rules.yaml          # 规则库
├── docs/                   # 文档
├── example/                # 示例代码
└── test/                   # 测试用例
```

## 🤝 贡献指南

欢迎提交 Issue 和 Pull Request！

1. Fork 本项目
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 创建 Pull Request

## 📄 许可证

本项目采用 Proprietary License，版权归 zhiyusec (HaoQing.Chen) 所有。

未经授权禁止使用。

## 🙋 支持与反馈

- **GitHub Issues**: https://github.com/zhiyusec/zhiyusec-leaks/issues
- **Email**: contact@zhiyusec.com
- **Website**: https://www.zhiyusec.com

---

**知御安全 zhiyusec** © 2025
先知 · 先御 · 智御未来
