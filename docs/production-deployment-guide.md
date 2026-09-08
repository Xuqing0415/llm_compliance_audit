# LLM Audit Gateway 生产部署指南

> 适用版本：v0.1.0。部署前请先读 [README.md](../README.md) 与 [SECURITY.md](../SECURITY.md)。
> 本指南基于仓库内实际资源编写：`deploy/k8s/deployment.yaml`、`deploy/docker/`、`configs/config.yaml`、`configs/exemptions.yaml`。

## 0. 目标读者与假设

读者：SRE / 安全团队，负责把网关接入真实 LLM 流量的维护者。

前提假设：

- 上游是 OpenAI 兼容 HTTP 服务（`/v1/chat/completions` 等）。
- 审计使用默认 `file` 存储、单副本部署（这是 v0.1.0 的受支持形态，见第 4.4 节）。
- 你可以在**一个非核心业务**上先灰度，而不是一上来就全量。

## 1. 架构与端口

```
客户端 ──> 网关 :8080 ──> 上游 LLM 服务
              │
              ├─ /v1/chat/completions、/v1/completions、其它任意路径（NoRoute 兜底转发）
              ├─ /health  /ready
              └─ /metrics（Prometheus 文本格式）

运维面 :9090
              ├─ /admin/*（需鉴权：admin_token 或 loopback）
              └─ /metrics
```

关键语义（v0.1.0 行为，务必理解）：

- **拦截先于放行**：非流式响应整体缓冲→扫描→下发；SSE 流式按滑动窗口「先检测、干净才 flush」。命中敏感内容，非流式返回 403，流式回终止帧。
- **purpose 由服务端推导**：客户端带 `X-Request-Purpose`/`X-Flow-Type` 不会改变策略；export 类路径（见 `path_purpose_mappings`）才走告警而非拦截。
- **审计是独立的第二道记录**：即使 bypass 全量放行，审计仍在写（只是不检测）。审计日志默认落在 `logs/audit/audit-YYYY-MM-DD.log`。

## 2. 生产配置清单

以 `configs/config.yaml` 为底，逐项核对：

| 配置位 | 生产建议 | 说明 |
| --- | --- | --- |
| `server.host/port` | `0.0.0.0:8080` | 主服务。 |
| `server.admin_port` | `9090` | 管理面端口，不要直接暴露公网。 |
| `server.admin_token` | **必填**，`openssl rand -hex 32` | 未设置时仅 loopback 可访问管理接口；设了 token 后所有 `/admin/*` 需带 `X-Admin-Token`。 |
| `server.max_request_body_size` | 按最大合法请求估算，默认 10MiB | 超出返回 413。 |
| `server.read_timeout` | 保持默认 30s | 写超时已移除（长流需要），读超时保留。 |
| `upstream.url` | 真实上游，如 `https://your-llm.example.com/v1` | 路径拼接已去重，带 `/v1` 不会出现 `/v1/v1`。 |
| `upstream.request_headers.Authorization` | 替换 `YOUR_API_KEY` | 生产用 Secret 注入或密钥管理，别提交明文。 |
| `audit.enabled` | `true` | 关闭等于审计网关失去意义。 |
| `audit.storage_type` | `file`（v0.1.0 唯一可用实现） | kafka/clickhouse 配置位为预留，未实现。 |
| `audit.audit_sampling_rate` | 1.0（全量）→ 0.1（压测） | `0<rate<1` 时只抽样写普通放行；拦截与高危命中**永远全量写**。 |
| `audit.log_retention_days` | 按合规要求，默认 90 | 仅对 file 存储生效，过期文件会被清理。 |
| `audit.max_disk_usage_percent` | 85 | 超阈值会暂停审计写入并告警（真实磁盘统计已实现）。 |
| `detection.audit_only_mode` | 灰度期 `true`，稳定后 `false` | 只告警不拦截，适合上线观察。 |
| `detection.tier1/2/3_enabled` | 保持 `true/false/false` | tier2/tier3 仍是占位实现，开了也只是空跑。 |
| `detection.parallel_detection` | `true` | 首命中即返回 + 记录延迟（已修复）。 |
| `detection.fail_open` | `true` 需谨慎 | `false` 时检测器出错直接 403，可用性换安全性。 |
| `detection.stream.*` | 默认即可 | 见第 5.2 节窗口权衡。 |
| `monitoring.enabled` | `true` | 同时暴露 `:8080/metrics` 与 `:9090/metrics`。 |

### 2.1 热更新

- `config.yaml` 支持热重载：用 `vim`/IDE 保存（含「先删后建」式保存）都会触发，日志出现 `Config file changed, triggering reload...` 与 `Config reloaded successfully` 即生效；无需重启。
- `exemptions.yaml` 单独热监听：修改后日志出现 `Exemptions file changed, reloading...`。
- **变更生效范围**：检测开关、规则、策略、路径映射等运行参数实时生效；需要重启才保证的项会在 Release Notes 注明。

## 3. 镜像构建

仓库内 `deploy/docker/Dockerfile` 为多阶段构建（golang:1.22-alpine 编译 → alpine:3.19 运行）。

```bash
# 本地验证
docker compose -f deploy/docker/docker-compose.yml build

# 推到你的 registry（K8s 用）
docker build -f deploy/docker/Dockerfile -t registry.example.com/llm-audit-gateway:v0.1.0 .
docker push registry.example.com/llm-audit-gateway:v0.1.0
```

`docker-compose.yml` 会把 `../configs/config.yaml`、`../configs/exemptions.yaml` 与 `../logs` 挂进容器；仅适合本地/单机验证，生产请用 K8s。

## 4. Kubernetes 部署

### 4.1 使用仓库自带的 deployment.yaml

`deploy/k8s/deployment.yaml` 已包含：Deployment（replicas=1、探针、资源限额）、config ConfigMap、exemptions ConfigMap、PVC（10Gi，RWO）、HPA（钉在 1 副本）。**上手前必改**：

1. `image: llm-audit-gateway:latest` → 你推的 registry 镜像 + 版本 tag。
2. ConfigMap `llm-audit-gateway-config` 里的 `config.yaml` 内容要与仓库 `configs/config.yaml` **保持同步**（含新增的 `admin_token` 字段），并显式设置 `admin_token`（留空时管理接口只能从 Pod 内 loopback 访问，运维等于不可用）。
3. ConfigMap 里 `upstream.url` / `Authorization` 替换为真实上游与密钥（生产建议改用 Secret 卷挂载 `config.yaml` 或启动时注入）。

```bash
kubectl apply -f deploy/k8s/deployment.yaml
kubectl rollout status deployment/llm-audit-gateway
```

### 4.2 Service 与入口

deployment.yaml 未附带 Service，按需创建：

```yaml
apiVersion: v1
kind: Service
metadata:
  name: llm-audit-gateway
  labels:
    app: llm-audit-gateway
spec:
  selector:
    app: llm-audit-gateway
  ports:
    - name: http
      port: 8080
      targetPort: 8080
    - name: admin
      port: 9090
      targetPort: 9090
```

- 业务流量只走 `:8080`；`:9090` 仅给运维网段/跳板机访问。
- 对上游出口建议固定 egress 白名单；对入口用 NetworkPolicy/防火墙限制来源。

### 4.3 存储与备份

- 审计日志在 PVC `llm-audit-logs`（`/app/logs/audit/audit-YYYY-MM-DD.log`），Pod 重建不丢。
- PVC 为 `ReadWriteOnce`，只支持单节点挂载——这正好约束了「单副本写审计」的形态。
- **备份**：每日把当日 audit 文件复制到对象存储/归档（见第 8 节），PVC 本身不是备份。

### 4.4 多副本边界（重要）

v0.1.0 审计链（`previous_hash` → `audit_hash`）是**单文件顺序追加**模型，哈希链依赖「上一行是谁」。多副本各自写文件会造成：

- 每个副本自建 `audit-YYYY-MM-DD.log`，链被拆成 N 条；
- 调度到不同节点时 `ReadWriteOnce` PVC 直接挂不上。

因此 deployment.yaml 强制 `replicas: 1`、HPA 钉 1。**想横向扩容，前提是先做 v0.2.0 的 Kafka sink**（把审计变成追加到集中 topic），在这之前不要改副本数。

## 5. 灰度与放量

目标：**先证明不误杀业务，再逐步开拦截**。推荐节奏：

1. **阶段 A — 旁路审计（audit_only_mode: true）**：放量 100% 流量，拦截逻辑不触发，只审计 + 报警。持续 3-7 天，跑第 7 节的误报分析。
2. **阶段 B — 影子拦截**：挑 1-2 条高置信规则（如身份证号校验位、银行卡 Luhn）先开 BLOCK，其余保持告警。
3. **阶段 C — 策略放量**：用 `POST /admin/policy/active` 切 `force-block`，先小流量再全量。
4. **回滚**：任意阶段出问题，`POST /admin/bypass {"enable": true}` 立即全量放行（审计继续写），或把 `audit_only_mode` 改回 `true` 热更新。

### 5.1 观察指标（阶段 A 期间）

- `/admin/stats`：放行/拦截计数与各检测器延迟（并行模式延迟已修复，不再恒为 0）。
- 审计日志每日去重命中统计（第 7.2 节命令）。
- 业务侧 P99 对比：网关纯转发开销应可忽略；真正成本来自响应缓冲与流式窗口延迟。

### 5.2 流式窗口权衡

`detection.stream` 决定 SSE 流「攒多少再放行」：

- `window_max_size`（默认 500）：滑窗最大长度，越大越能跨块检测，但内存与首字延迟越高。
- `window_flush_threshold`（默认 50）+ `max_delay_ms`（默认 300）：攒满 50 字符或 300ms 就 flush 一批。**命中前已 flush 的内容无法撤回**——这是流式协议的物理约束，不是 bug。对强合规场景可调小窗口，或让关键路径走非流式（`Accept: application/json`）。

## 6. 可观测性

### 6.1 指标端点现状

- `:8080/metrics` 与 `:9090/metrics` 均输出 Prometheus 文本格式，但**当前只有运行时指标**（`go_*`、`process_*`、`promhttp_*`），没有业务计数器（拦截量、P99 等）——业务信号在 `/admin/stats`（JSON）和审计日志里。
- K8s 里 `deployment.yaml` 已带 `prometheus.io/scrape: "true"`（9090）。用 Prometheus 注解发现即可；若用 Prometheus Operator，创建带 `metrics` 端口名的 Service 后加 ServiceMonitor 即可。

### 6.2 业务信号接入（现状下的务实做法）

在 v0.2.0 内置业务指标前，二选一：

- **黑盒探活**：Prometheus 每 15s `GET /health` + `GET /admin/stats`（带 token）判断存活与拦截可用。
- **文本文件采集（textfile collector）**：用 CronJob 每小时把 `/admin/stats` 关键数字写进 node_exporter 的 `*.prom` 文件，之后业务告警就能引用。下列告警文件里已预留注释位。

告警规则见 [deploy/prometheus/alerts.yml](../deploy/prometheus/alerts.yml)；规则里 `job="gateway"` 是占位标签，请按你 Scrape 配置的实际 job 名调整。

### 6.3 Grafana

v0.1.0 未附带面板 JSON（规划中）。最小面板建议：Go 运行时（内存/goroutine/GC）、`up`、PVC 磁盘水位、`/admin/stats` 文本指标。

## 7. 误报分析与豁免回收

### 7.1 审计日志格式

审计文件把多条 **pretty-printed JSON 对象**顺序追加（每条记录内部多行、记录间以换行分隔）；解析请用流式解码器（`jq` 或各语言的 `JSONDecoder`），**不要按行切分**。字段示例：

```json
{
  "timestamp": "...", "request_id": "...", "trace_id": "...",
  "request_body": "脱敏后正文", "request_body_hash": "sha256(原文)",
  "response_body": "脱敏后正文", "response_body_hash": "...",
  "action": "BLOCK", "detection_results": [
    {"matched": true, "hit_rule_id": "身份证号", "matched_text": "脱敏后的命中文本", "severity": "HIGH"}
  ],
  "audit_hash": "...", "previous_hash": "..."
}
```

注意：`matched_text` 落盘前已脱敏（打码），拿它做聚合键没问题，但别期待能还原原文。

### 7.2 统计每日 Top 命中（推荐命令）

```bash
# 某天的 top 规则×文本 组合
jq -r 'select(.detection_results != null)
       | .detection_results[]
       | select(.matched == true and .hit_rule_id != "")
       | [.hit_rule_id, .matched_text] | @tsv' \
  /app/logs/audit/audit-2026-09-08.log \
  | sort | uniq -c | sort -rn | head -20
```

仓库内 `scripts/analyze_false_positives.ps1` 提供同类统计（含业务关键词字典）；其按行解析假定单行 JSON，若仓库审计文件为 pretty JSON 请先 `jq -c .` 压平再喂给它。

### 7.3 豁免的两种入口

| 入口 | 持久性 | 适用 |
| --- | --- | --- |
| `POST /admin/whitelist`（关键词 add/remove） | 写回 `exemptions.yaml` | 临时放行、快速止血 |
| 直接改 `exemptions.yaml` 的 `false_positives.patterns`（正则，匹配命中文本） | 文件本身（热重载） | 可沉淀的误报模式，建议走评审 |

两点注意：

- `/admin/whitelist` 的持久化会**重写整个 exemptions.yaml**（只保留 `exemptions` 与 `false_positives` 两组结构），不要在该文件里放其它顶层自定义键；提交前留意变更 diff。
- 豁免会削弱检测——**任何豁免都应记录原因与负责人**，并在每周误报评审里复核。

### 7.4 定时回收 CronJob（示例）

挂载审计 PVC，每天 00:30 跑一次 Top 命中统计并把结果打到标准输出（供日志采集/通知）：

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: audit-fp-analysis
spec:
  schedule: "30 0 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: OnFailure
          containers:
            - name: fp-analysis
              image: python:3-alpine
              command: ["sh", "-c"]
              args:
                - |
                  python - <<'PY'
                  import json, collections, glob
                  c = collections.Counter()
                  for f in glob.glob('/logs/audit/audit-*.log'):
                      with open(f) as fh:
                          text = fh.read()
                      dec = json.JSONDecoder()
                      i = 0
                      while i < len(text):
                          while i < len(text) and text[i] in ' \n\t\r': i += 1
                          if i >= len(text): break
                          try:
                              obj, i = dec.raw_decode(text, i)
                          except ValueError:
                              i += 1
                              continue
                          for r in obj.get('detection_results') or []:
                              if r.get('matched') and r.get('hit_rule_id'):
                                  c[(r['hit_rule_id'], r.get('matched_text', ''))] += 1
                  for (rule, text), n in c.most_common(20):
                      print(f'{n}\t{rule}\t{text}')
                  PY
              volumeMounts:
                - name: logs
                  mountPath: /logs
          volumes:
            - name: logs
              persistentVolumeClaim:
                claimName: llm-audit-logs
```

（脚本会打印脱敏命中文本；生产可把输出接到内部 IM/工单做人工复核。）

## 8. 审计完整性运维

每条记录的 `previous_hash`/`audit_hash` 构成链：`audit_hash = SHA256(previous_hash | 规范化记录内容)`，正文与摘要都在哈希覆盖内——**改任何一行都会断链**。v0.1.0 尚未内置「验链」工具（v0.2.0 候选），当前运维手段：

1. **文件不可变**：审计 PVC 只让网关写；巡检人员只读。
2. **每日归档到对象存储**：`audit-YYYY-MM-DD.log` 按天落盘后复制到独立桶（保留策略按合规），副本用于事后比对。
3. **周期抽查**：对关键记录手工复算链路；发现断链按事件升级处理（恢复流程：从归档副本恢复当日文件，重启网关续链——注意续链需要与上一记录哈希一致，务必以归档副本为准）。

> 提示：不要把审计日志随便删行/合并，任何手工编辑都会断链。清理策略只应通过 `audit.log_retention_days`（过期整文件删除）执行。

## 9. 日常巡检与排障

| 现象 | 第一步排查 |
| --- | --- |
| 业务 403 变多 | 看 403 body 的 `detection_id` → `GET /admin/audit/trace?trace_id=<detection_id>` 查记录与命中规则；确认是误报走第 7 节豁免流程 |
| 流式回答被中途终止 | body 出现「检测到敏感数据，已终止生成」说明命中规则；调小/审查豁免 |
| 审计文件不涨 | `audit.enabled`？磁盘 `max_disk_usage_percent` 是否触发（日志有 Warn）？PVC 是否只读？ |
| 管理接口 403 | 忘了 `X-Admin-Token` 或 token 不匹配；未设 token 时确认来源是 loopback |
| 内存暴涨 | 检查是否有超大非流式响应（>64MB 会直接 502，正常应看不到）；确认 `max_request_body_size` 合理 |
| 需要立即止血 | `POST /admin/bypass {"enable": true}`（审计继续写），再走流程 |

巡检节奏建议：每日看 `up`/磁盘/`/admin/stats`；每周跑第 7.2 节误报统计 + 复核豁免清单。

## 10. 上线检查清单

- [ ] `admin_token` 已设置且只在内网传播
- [ ] `upstream.url`/`Authorization` 指向真实上游（非占位符）
- [ ] K8s 镜像 tag 已更新、config/exemptions ConfigMap 内容与仓库一致
- [ ] PVC 就绪且备份任务已配置（第 8 节）
- [ ] `audit_only_mode` 先开 `true`，误报统计跑通一周
- [ ] Prometheus 抓 `:9090/metrics` 正常，`alerts.yml` 已加载（先跑 1-2 天看告警是否贴合）
- [ ] 团队已知 bypass/force-block 的触发方式与审批人
- [ ] 已读 [SECURITY.md](../SECURITY.md) 部署清单

## 11. 已知边界（写进你的内部周报）

- tier2/tier3 为占位实现（默认关闭），当前拦截以 tier1 正则为准。
- 业务级 Prometheus 指标与审计验链工具尚未内置（v0.2.0 Roadmap）。
- 审计 file 存储单实例；多副本必须先做 Kafka sink。
- 网关只保护经过它的流量——请确保客户端无法直连上游。
