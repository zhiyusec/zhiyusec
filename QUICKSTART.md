# 🚀 快速开始指南

## 1. 构建项目

```bash
# 克隆或进入项目目录
cd zhiyusec-leaks

# 构建可执行文件
go build -o zhiyusec-leaks cmd/zhiyusec-leaks/main.go
```

## 2. 查看帮助

```bash
./zhiyusec-leaks --help
```

## 3. 运行测试扫描

```bash
# 扫描test目录（包含测试样本）
./zhiyusec-leaks test -f json,html -o test-reports --no-progress
```

## 4. 查看扫描结果

```bash
# 查看JSON报告
cat test-reports/zhiyusec-scan-*.json

# 或在浏览器中打开HTML报告
open test-reports/zhiyusec-scan-*.html  # macOS
# xdg-open test-reports/zhiyusec-scan-*.html  # Linux
```

## 5. 扫描实际项目

```bash
# 扫描当前项目（排除test目录）
./zhiyusec-leaks . -f html -o reports --no-progress

# 扫描指定目录
./zhiyusec-leaks /path/to/your/project -f json,html

# 使用配置文件
./zhiyusec-leaks -c configs/zhiyusec.yaml
```

## 6. 自定义配置

编辑 `configs/zhiyusec.yaml` 文件：

```yaml
scan:
  paths: ["."]
  max_file_size: 104857600  # 100MB
  blacklist:
    - "node_modules"
    - "\\.git"
    - "vendor"

detect:
  enable_builtin_rules: true
  entropy_threshold: 4.5

report:
  formats: ["json", "html"]
  output_dir: "reports"
  min_severity: "medium"  # 只报告中危及以上

performance:
  max_concurrency: 10
```

## 7. 添加自定义规则

创建 `my-rules.yaml`：

```yaml
version: "1.0.0"
rules:
  - id: "my-secret"
    description: "检测自定义密钥"
    type: "api_key"
    pattern: 'MY_SECRET_[A-Z0-9]{32}'
    severity: "high"
    enabled: true
```

在配置文件中添加：

```yaml
detect:
  rule_files:
    - "configs/rules.yaml"
    - "my-rules.yaml"
```

## 8. CI/CD 集成

### GitHub Actions

```yaml
name: Secret Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Setup Go
        uses: actions/setup-go@v2
        with:
          go-version: '1.25'
      - name: Install zhiyusec-leaks
        run: go install github.com/zhiyusec/zhiyusec-leaks/cmd/zhiyusec-leaks@latest
      - name: Run scan
        run: zhiyusec-leaks -f sarif -o results .
      - name: Upload results
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results/*.sarif
```

## 9. 编程接口使用

```go
package main

import (
    "context"
    "log"

    "github.com/zhiyusec/zhiyusec-leaks/pkg/config"
    "github.com/zhiyusec/zhiyusec-leaks/pkg/runner"
)

func main() {
    // 创建配置
    cfg := config.DefaultConfig()
    cfg.Scan.Paths = []string{"."}

    // 创建运行器
    r, err := runner.NewRunner(cfg)
    if err != nil {
        log.Fatal(err)
    }

    // 运行扫描
    if err := r.Run(context.Background()); err != nil {
        log.Fatal(err)
    }

    // 获取结果
    result := r.GetResult()
    log.Printf("发现 %d 个敏感信息\n", len(result.Findings))
}
```

## 10. 常见问题

### Q: 扫描速度慢？
A: 调整并发数 `--max-concurrency 20`

### Q: 误报太多？
A: 调整熵值阈值或添加排除规则

### Q: 如何只扫描特定文件类型？
A: 使用白名单正则表达式：
```yaml
scan:
  whitelist:
    - "\\.js$"
    - "\\.py$"
```

### Q: 如何排除某些目录？
A: 使用黑名单：
```yaml
scan:
  blacklist:
    - "node_modules"
    - "vendor"
    - "\\.git"
```

## 11. 更多资源

- 完整文档: [docs/USAGE.md](docs/USAGE.md)
- API示例: [example/basic_usage.go](example/basic_usage.go)
- 项目总结: [PROJECT_SUMMARY.md](PROJECT_SUMMARY.md)
- GitHub: https://github.com/zhiyusec/zhiyusec-leaks

---

**知御安全 zhiyusec** © 2025