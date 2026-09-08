# 安全说明（SECURITY.md）

本文件面向将本网关用于生产环境的部署者与安全评审者，说明安全立场、已修复问题与部署要求。

## 安全立场

这个网关的职责是两件事：**先拦住，再留痕**。

- **拦截先于泄露**：所有响应在放行给调用方前必须通过检测——非流式整体缓冲后裁决，流式按窗口先检测再 flush；命中即中止，不允许「东西先出去、事后再补 403」。
- **规则归属服务端**：请求的 purpose、执行策略、是否响应扫描均由服务端配置与路径推导，客户端请求头（`X-Request-Purpose`、`X-Flow-Type`、`X-Export-Scope` 等）不能自我声明豁免。
- **审计记录本身不成为泄露源**：日志只落脱敏正文与原文哈希；哈希链覆盖正文，正文被改动即可被发现；任何情况下不静默丢记录。

## v0.1.0 修复的安全问题

对应 [CHANGELOG.md](CHANGELOG.md) 的详细条目，摘要如下：

| 类别 | 问题 | 处置 |
| --- | --- | --- |
| 拦截 | 流式窗口内容先发给客户端再检测，敏感内容必然先泄露 | 改为先检测后放行（窗口级） |
| 拦截 | 非流式响应原样透传后才补 403，形同虚设 | 缓冲→扫描→下发，命中 403 |
| 绕过 | `X-Request-Purpose: export` 可让调用方自降 BLOCK 为 ALERT 并关闭响应扫描 | purpose 只由服务端推导 |
| 转发 | 检测截断污染上游请求体（大于 2000B 的流式请求发半截 JSON） | 转发始终用完整 body |
| 转发 | `/v1/v1` 路径拼接、请求体大小未真限制 | 路径去重、`http.MaxBytesReader` |
| 鉴权 | 管理接口零鉴权，任意 `curl` 可开 bypass | `admin_token` 或 loopback-only |
| 审计 | PII 明文落盘、哈希链不含正文、缓冲满/关停丢记录 | 脱敏 + 原文哈希、哈希覆盖正文、同步兜底 + 排空 |
| 审计 | 磁盘保护为 0% 空壳 | `golang.org/x/sys` 真实统计 |
| 部署 | 日志容器盘易失、豁免文件未挂载、Compose 构建失败 | PVC/ConfigMap 挂载、路径修正 |

## 部署安全清单（生产前逐项确认）

1. **设置 `server.admin_token`**：生成随机值（如 `openssl rand -hex 32`），通过 `X-Admin-Token` 请求头调用管理接口；不要把 token 提交到仓库。
2. **配置真实上游与密钥**：`configs/config.yaml` 中 `upstream.request_headers.Authorization` 当前是占位符 `YOUR_API_KEY`；生产用环境变量注入或密钥管理替换，并保证该文件不被公开。
3. **审计落盘**：审计默认 `file` 存储仅适合单实例。K8s 下必须使用随部署附带的 PVC；多副本或高吞吐请先接入集中存储（kafka 适配未落地前不要横向扩容，部署文件已强制 `replicas: 1`）。
4. **灰度策略**：新规则误报风险高。先在 `audit_only_mode: true` 下观察，再用 `POST /admin/policy/active` 切 `force-block`。
5. **指标与日志面**：`/metrics` 免鉴权，切勿直接暴露到公网；审计日志为脱敏文本，仍需按合规要求做访问控制与保留策略（`log_retention_days`）。
6. **依赖更新**：关注 `go.mod` 中 `golang.org/x/*` 与 gin/prometheus 等依赖的 CVE 公告并及时升级。

## 已知限制与边界

- **tier2（PII 语义）与 tier3（语义风险）检测器是占位实现**（默认关闭）。当前拦截能力以 tier1 正则为主，覆盖面有限，不能替代专门的数据防泄漏（DLP）与内容风控方案。
- 正则规则（命令/SQL 注入等）存在误报与漏报；建议按流量回放调优（参考 `scripts/analyze_false_positives.ps1`）。
- 本网关只对经过它的流量生效；若调用方直连上游，则任何能力都不适用，请用网络策略强制流量经过网关。
- 流式输出的窗口缓冲意味着命中前的少量已 flush 内容无法撤回（受 `detection.stream.window_flush_threshold` / `max_delay_ms` 控制），如需更强约束可调小窗口或对该类流量改用非流式。

## 漏洞报告

请通过 [GitHub Issues](https://github.com/Xuqing0415/llm_compliance_audit/issues) 报告安全问题，标题标注 `[security]`，并附复现步骤、影响面与建议修复。公开仓库请勿在 issue 中直接粘贴真实生产数据/密钥。