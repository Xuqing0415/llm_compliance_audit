# 贡献指南（CONTRIBUTING.md）

欢迎 Issue 与 PR。在动手前请先阅读 [README.md](README.md) 与 [SECURITY.md](SECURITY.md)，尤其是「已知限制」一节——**tier2/tier3 目前是占位实现**，涉及它们的改动请先开 Issue 对齐方向。

## 开发环境

- Go 1.22+（见 `go.mod`）
- 上游需要一个 OpenAI 兼容的服务用于联调；`configs/config.yaml` 中 `upstream.url` 与 `Authorization` 请改为本地/测试值
- 无需外部数据库：审计默认 `file` 存储，日志落在 `logs/audit/`（已被 `.gitignore` 排除）

## 常用命令

```bash
go build ./...     # 编译
go vet ./...       # 静态检查
go test ./...      # 全部测试（含 internal/smoke 回归套件）
go test ./internal/smoke/ -run TestProxyAndServer -v   # 单测快速验证
gofmt -l .         # 确认无格式问题（新代码必须 gofmt 干净）
```

提交前请确保三件套全绿：`go build ./...`、`go vet ./...`、`go test ./...`。

## 代码风格

- 新增/修改文件必须通过 `gofmt`；不要顺手把无关的存量文件全量重排，保持 diff 聚焦。
- 错误处理显式；不要在审计写入路径上静默丢记录（这是本项目的红线，见 [SECURITY.md](SECURITY.md)）。
- 日志统一使用 `logrus`，中文注释与提交信息均可接受，代码标识符用英文。
- 安全相关改动（proxy 拦截顺序、purpose 推导、审计脱敏/哈希链）必须补回归用例到 `internal/smoke/`。

## 提交 PR

1. 先开 Issue 说明动机与方案（bug 请给复现步骤）。
2. 分支命名建议 `fix/xxx`、`feat/xxx`、`docs/xxx`。
3. PR 标题格式：`<type>: <简短描述>`，例如 `fix: request purpose must be server-derived`。
4. PR 描述里关联 Issue（`Closes #12`），列出改动文件与验证结果（build/vet/test 输出）。
5. 若改动会改变对外行为（配置字段、管理 API、检测语义），请在 PR 里同步更新 README/CHANGELOG 并写清兼容性影响。

## 什么改动会优先合入

- 修 bug 与补回归测试 > 文档与部署示例 > 新功能。
- 涉及 tier2/tier3 集成的大改动，先出设计说明（检测器接口、配置开关、误报策略）再动代码。
- 不引入新依赖前请评估必要性；确需引入请在 PR 说明维护成本与许可证兼容性。

## 行为准则

保持友善与建设性。安全漏洞**不要**发在公开 Issue，请走 [SECURITY.md](SECURITY.md) 的私有披露渠道。