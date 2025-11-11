.PHONY: build clean test install run help

# 项目信息
APP_NAME=zhiyusec-leaks
VERSION=1.0.0
BUILD_DIR=build
MAIN_FILE=cmd/zhiyusec-leaks/main.go

# Go 相关
GO=go
GOFLAGS=-v
LDFLAGS=-ldflags "-X main.version=$(VERSION)"

# 默认目标
.DEFAULT_GOAL := help

## help: 显示帮助信息
help:
	@echo "知御安全 zhiyusec-leaks Makefile"
	@echo ""
	@echo "使用方法:"
	@echo "  make <target>"
	@echo ""
	@echo "可用目标:"
	@sed -n 's/^##//p' $(MAKEFILE_LIST) | column -t -s ':' | sed -e 's/^/ /'

## build: 构建项目
build:
	@echo "构建 $(APP_NAME)..."
	$(GO) build $(GOFLAGS) $(LDFLAGS) -o $(APP_NAME) $(MAIN_FILE)
	@echo "构建完成: ./$(APP_NAME)"

## build-all: 为所有平台构建
build-all:
	@echo "为所有平台构建..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 $(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(APP_NAME)-linux-amd64 $(MAIN_FILE)
	GOOS=linux GOARCH=arm64 $(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(APP_NAME)-linux-arm64 $(MAIN_FILE)
	GOOS=darwin GOARCH=amd64 $(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(APP_NAME)-darwin-amd64 $(MAIN_FILE)
	GOOS=darwin GOARCH=arm64 $(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(APP_NAME)-darwin-arm64 $(MAIN_FILE)
	GOOS=windows GOARCH=amd64 $(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(APP_NAME)-windows-amd64.exe $(MAIN_FILE)
	@echo "所有平台构建完成: $(BUILD_DIR)/"

## install: 安装到系统
install: build
	@echo "安装 $(APP_NAME)..."
	$(GO) install $(LDFLAGS) $(MAIN_FILE)
	@echo "安装完成"

## clean: 清理构建文件
clean:
	@echo "清理构建文件..."
	@rm -f $(APP_NAME)
	@rm -rf $(BUILD_DIR)
	@rm -rf test-reports
	@rm -rf reports
	@echo "清理完成"

## test: 运行测试
test:
	@echo "运行测试..."
	$(GO) test -v ./...

## run: 运行项目
run: build
	@echo "运行 $(APP_NAME)..."
	./$(APP_NAME) test -f json,html -o test-reports --no-progress

## scan: 扫描当前项目
scan: build
	@echo "扫描当前项目..."
	./$(APP_NAME) . -f html -o reports --no-progress

## fmt: 格式化代码
fmt:
	@echo "格式化代码..."
	$(GO) fmt ./...

## vet: 代码静态检查
vet:
	@echo "代码静态检查..."
	$(GO) vet ./...

## lint: 代码lint检查
lint:
	@echo "运行golangci-lint..."
	@which golangci-lint > /dev/null || (echo "请先安装golangci-lint: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest" && exit 1)
	golangci-lint run

## deps: 下载依赖
deps:
	@echo "下载依赖..."
	$(GO) mod download
	$(GO) mod tidy

## update: 更新依赖
update:
	@echo "更新依赖..."
	$(GO) get -u ./...
	$(GO) mod tidy

## version: 显示版本信息
version:
	@echo "$(APP_NAME) v$(VERSION)"

## demo: 运行演示
demo: build
	@echo "运行演示..."
	@echo "1. 扫描test目录..."
	./$(APP_NAME) test -f json,html -o test-reports --no-progress
	@echo ""
	@echo "2. 查看JSON报告..."
	@cat test-reports/zhiyusec-scan-*.json | head -30
	@echo ""
	@echo "3. HTML报告已生成在: test-reports/"
	@ls -lh test-reports/*.html

## docker-build: 构建Docker镜像
docker-build:
	@echo "构建Docker镜像..."
	docker build -t $(APP_NAME):$(VERSION) .
	docker tag $(APP_NAME):$(VERSION) $(APP_NAME):latest

## docker-run: 运行Docker容器
docker-run:
	@echo "运行Docker容器..."
	docker run --rm -v $(PWD):/workspace $(APP_NAME):latest /workspace

.PHONY: all
all: clean deps build test