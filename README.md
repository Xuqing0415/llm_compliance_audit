# LLM Compliance Audit Gateway（LLM 合规审计网关）

> **Status**: v0.1.0 · 首个公开版。代码与文档已冻结，可试用；生产接入前请逐项对照 [SECURITY.md](SECURITY.md) 部署清单。

[![Go](https://img.shields.io/badge/Go-1.25+-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![Release](https://img.shields.io/github/v/release/Xuqing0415/llm_compliance_audit)](https://github.com/Xuqing0415/llm_compliance_audit/releases)
[![License](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

面向 LLM/OpenAI 兼容服务的合规审计反向代理：在模型 API 前加一层网关，对进出流量做**敏感数据出境**、**提示词注入**、**命令/SQL 注入**、**批量导出**检测，并把拦截与放行过程记录成**防篡改审计日志**。

> 当前版本：**v0.1.0**（首个公开版）。本版修复了安全审查发现的「先泄露后拦截」「请求头伪造绕过」「审计明文落盘 + 哈希链失效」等核心问题，修复摘要见 [CHANGELOG.md](CHANGELOG.md)，安全设计与部署要求见 [SECURITY.md](SECURITY.md)。

## 功能特性

- **请求检测**：中国身份证号 / 手机号 / 银行卡号 / 邮箱等 PII 出境默认 BLOCK；提示词注入指纹、命令注入、SQL 注入单独规则；`configs/config.yaml` 的 `detection.regex_rules` 可热重载。
- **响应检测（先拦后放）**：非流式响应整体缓冲→扫描→下发，命中即 403，敏感内容零泄露；SSE 流式响应按滑动窗口「先检测、干净才放行」，命中即向客户端回终止帧。
- **场景化策略**：purpose（chat / export / codegen …）由**服务端按路径推导**，客户端无法用 `X-Request-Purpose` 之类请求头自封 export 降级拦截；`force_audit` 仅对 export 类目的生效。
- **审计留痕**：落盘正文脱敏（身份证 / 手机号 / 银行卡 / 邮箱打码）+ 存原文 SHA-256；SHA-256 链式哈希覆盖正文，防篡改；日志缓冲满不丢记录、优雅关停排空落盘。
- **管理面 HTTP API**：bypass / 规则开关 / 豁免白名单（持久化回 `exemptions.yaml`）/ 全局策略切换 / 审计查询 / Prometheus 指标。

## 快速开始

环境要求：Go 1.25+（见 `go.mod`），目标服务为 OpenAI 兼容 HTTP API。

```bash
# 1. 构建
go build -o gateway ./cmd/gateway

# 2. 配置 configs/config.yaml
#    - upstream.url 改为你的模型服务，如 http://your-llm-host:8000/v1
#    - upstream.request_headers.Authorization 换成真实密钥（当前为占位符 YOUR_API_KEY）
#    - 生产必须设置 server.admin_token（随机串），否则管理接口仅本机可访问

# 3. 启动
./gateway -config configs/config.yaml

# 4. 请求示例（由网关转发到上游并检测）
curl -s http://localhost:8080/v1/chat/completions -H 'Content-Type: application/json' -d '{
  "model": "gpt-4o-mini",
  "messages": [{"role": "user", "content": "帮我总结这段话"}]
}'
```

容器 / Kubernetes 部署：

```bash
# Docker Compose（构建上下文为仓库根，配置与豁免文件挂载自 configs/）
docker compose -f deploy/docker/docker-compose.yml up --build

# Kubernetes（含 config/exemptions ConfigMap、审计日志 PVC 10Gi）
kubectl apply -f deploy/k8s/deployment.yaml
```

## 管理面

管理服务监听 `server.admin_port`（默认 9090）。鉴权规则：

- 配置了 `server.admin_token` 时，所有 `/admin/*` 请求必须带请求头 `X-Admin-Token: <token>`；
- 未配置时，仅 loopback（127.0.0.1 / ::1）可访问，外部网络调用返回 403；
- `/health`、`/ready`、`/metrics` 不需要鉴权（指标随 admin 端口暴露，生产请用网络策略限流）。

常用接口（管理面均在 `/admin` 前缀下）：

| 接口 | 说明 |
| --- | --- |
| `POST /admin/bypass` | `{"enable": true\|false}` 开启/关闭全量放行（谨慎使用） |
| `POST /admin/rules/toggle` | `{"rule_name": "...", "enable": bool}` 启停规则 |
| `POST /admin/whitelist` | `{"rule_name","keyword","action":"add\|remove"}` 豁免关键词（会写回文件） |
| `POST /admin/policy/active` | `{"set":"default\|fallback-audit\|force-block"}` 全局策略 |
| `GET /admin/audit/trace?trace_id=...` | 按 trace/request id 查审计记录 |
| `GET /metrics` | Prometheus 指标（`promhttp`） |

## 测试

```bash
go build ./...
go vet ./...
go test ./...          # 含 internal/smoke 回归套件
```

冒烟套件覆盖：敏感请求 403 且**响应零泄露**、伪造 `X-Request-Purpose` 不绕过、`enable:false` 可关闭 bypass、指纹规则单特征命中、审计日志脱敏 + 哈希链、白名单持久化、9090 指标可用等。测试日志写入临时目录，不污染仓库。

## 已知限制（生产前请阅读）

- **tier2 PII 识别与 tier3 语义检测为占位实现**（默认关闭 `tier2_enabled`/`tier3_enabled`），当前能力以 tier1 正则为主。
- 审计默认 `file` 存储、适合单实例；多副本/高吞吐需接入集中式存储（kafka 适配目前未落地），见 [SECURITY.md](SECURITY.md) 部署清单。
- 命令/SQL 注入等正则规则存在误报可能，上线建议先 `audit_only_mode: true` 灰度观察（配置见 `configs/config.yaml`，辅助脚本见 `scripts/analyze_false_positives.ps1`）。
- **部分配置项为预留字段**：`server.write_timeout`、`upstream.timeout`、`audit.max_log_file_size_mb`、`detection.export_batch_threshold`、`detection.policy_guard`、`monitoring.prometheus_url` 当前未被代码消费，改动不会生效（`configs/config.yaml` 顶部有同样说明），计划在 v0.2.0 落实。

## Roadmap（v0.2.0 方向）

按「让生产部署更平滑」排序，社区反馈会调整优先级：

- **Tier 2 PII 识别引擎落地**：当前 `internal/detector/tier2_pii.go` 为占位实现（默认关闭），v0.2.0 计划接入真实 PII 识别并保留现有开关语义。
- **审计输出 Kafka sink**：`configs/config.yaml` 已预留 `audit.storage_type: kafka` 配置位，替代本地 `file` 存储，支撑多副本/高吞吐。
- **Prometheus 告警规则示例**：随仓库提供 `alerts.yml`，覆盖拦截量突增、审计写盘失败、磁盘水位等关键信号。
- **生产部署实战文档**：已提供 [docs/production-deployment-guide.md](docs/production-deployment-guide.md)（K8s 模板、灰度放量、误报回收 CronJob、排障清单）；Grafana 面板 JSON 仍规划中。
- **Tier 3 语义检测（可选开关）**：仅在社区反馈「Tier1+Tier2 不够用」时推进。

## 目录结构

```text
cmd/gateway         入口：装配 config/detector/pipeline/audit/server/watcher
internal/config     配置加载、热重载（fsnotify，支持 vim 式 rename 保存）
internal/detector   tier1 正则 / tier2 PII（stub）/ tier3 语义（stub）/ 豁免管理
internal/pipeline   串行/并行/流式检测流水线
internal/proxy      转发与流式/非流式拦截核心
internal/audit      审计日志（脱敏、哈希链、磁盘保护、会话聚合）
internal/server     主服务与管理服务（admin_token 鉴权、/metrics）
internal/smoke      回归冒烟测试
configs             配置与豁免文件
deploy              Docker Compose / Kubernetes 部署
```
