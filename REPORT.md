# Security Audit Report — magic-api v2.2.2

**Target:** https://github.com/ssssssss-team/magic-api  
**Audit date:** 2026-09-10  
**Auditor:** Single-agent (no subagent primitives available; self-validated)  
**Output dir:** `~/security-audit-skill/magic-api/run-1`

## Executive Summary

magic-api 是一个低代码 API 构建平台，核心功能是通过 Web 工作台编写、保存并执行 magic-script 脚本（等价于任意 Java 代码）。产品**默认配置未开启认证**（`magic-api.security.username`/`password` 默认 `null`），且大量管理接口（脚本保存/删除、数据源连接测试、备份读取/回滚、上传/推送）既无 `@Valid` 注解也无 `allowVisit` 授权调用。

在默认配置下，**任何可访问应用 HTTP 端口的攻击者均可获得完整的远程代码执行能力**。这是已知高危产品缺陷（CNVD/社区常见利用）。

| Severity | Count |
|----------|-------|
| CRITICAL | 1 |
| HIGH     | 3 |
| MEDIUM   | 3 |
| LOW      | 1 |
| **Total**| **8** |

---

## Finding Summary

| ID | Title | Severity |
|----|-------|----------|
| F-01 | 默认配置下工作台完全无认证，导致未授权远程代码执行 | **CRITICAL** |
| F-02 | 未认证 JDBC 连接测试接口导致 SSRF，可在常见驱动下升级为 RCE | HIGH |
| F-03 | 未认证读取全部 API 脚本源码，泄露业务逻辑与嵌入凭证 | HIGH |
| F-04 | 未认证备份导出与全量回滚：可读全部脚本并可覆写工作区 | HIGH |
| F-05 | 工作台 /push 接口允许 SSRF：攻击者控制 RestTemplate 目标地址 | MEDIUM |
| F-06 | 认证令牌为无盐静态 MD5、永不过期、登出无失效 | MEDIUM |
| F-07 | 推送接收接口签名无时效校验，可重放实现工作区整体替换 | MEDIUM |
| F-08 | CORS 反射任意 Origin 并允许携带凭证（工作台路径） | LOW |

---

## Phase 6 — Independent Verification Notes

对核心调用链逐文件重读确认（与初始审计结果无矛盾）：

- `DefaultAuthorizationInterceptor` 第 21 行：`this.requireLogin = username != null && password != null` —— 默认 `Security.username/password` 为 `null` → `requireLogin=false` ✓
- `MagicWebRequestInterceptor.handle` 第 34-39 行：`requiredLogin=false` → 跳过 token 校验 → `doValid(request, null)` 不做任何检查 ✓
- `MagicController.doValid` 第 42-51 行：`valid==null` 时直接 return ✓
- `AuthorizationInterceptor.allowVisit` 第 66-68 行：`default return true` ✓
- `MagicDataSourceController.test`：无 `@Valid`、无 `allowVisit` 调用 ✓
- `JdbcUtils.getConnection`：`Class.forName(driver)` + `DriverManager.getConnection(url)`，`driver`/`url` 完全来自请求体 ✓
- `MagicBackupController`：全部方法无 `@Valid`、无 `allowVisit` ✓
- `ScriptManager.executeScript`：`MagicScript.create(script, null).execute(context)` ✓
- `MagicResourceLoader` 静态初始化：`addPackage("java.lang.*")`、`addPackage("java.util.*")` —— 脚本可直接使用 `ProcessBuilder`/`Runtime` 等任意 Java 类 ✓
- `DefaultMagicAPIService.push` 第 174 行：`restTemplate.postForObject(target, ...)`，`target` 来自请求 header ✓
- `receivePush` 第 337 行：`sign.equals(...)` 无 timestamp 新鲜度校验 ✓
- `MagicCorsFilter.process` 第 12-14 行：Origin → ACAO + ACAC:true ✓

---

## Prior Runs

本仓库无前序审计记录（run-1）。上表即全部发现。

---

## Methodology

1. **Phase 1 (Recon):** 阅读 pom.xml、README、全部 Controller/Interceptor/Service/Utils 源码，绘制认证/授权/执行数据流。由单 agent 完成（无 Task 委托）。
2. **Phase 2 (Hunt):** 按 OWASP + product-specific 攻击面（认证旁路、注入、SSRF、逻辑缺陷、CORS）逐接口审查；跟踪 magic-script 引擎确认任意类加载路径。
3. **Phase 3 (Validate):** 每个 finding 从入口到 sink 追踪完整调用链，记录精确文件/行号；排除误报（zip slip、文件名遍历、fastjson autotype）。
4. **Phase 4 (Report):** 本文件 + FINDINGS-DETAIL.md。
5. **Phase 5 (Structured):** `findings.json` 经 `validate-findings.cjs` 校验通过（8/8 valid）。
6. **Phase 6 (Verification):** 独立重读所有关键行号与逻辑，与 Phase 2-3 结论一致。

---

## Cleared Risks (no finding)

| 项目 | 原因 |
|------|------|
| Zip Slip (archive 解压) | `ZipResource` 在内存中解压为 map；文件名经 `IoUtils.FILE_NAME_PATTERN` 过滤（`^(?!\.)[\u4e00-\u9fa5_a-zA-Z0-9.\-()]+$`），不包含 `..`/路径分隔符 |
| fastjson autotype 反序列化 | 主 pom 有 `fastjson:1.2.83`（最后安全版本），实际 HTTP 层 JSON 序列化使用 Jackson，fastjson 不在可被触发的调用链上 |
| configJs 路径遍历 | `/config-js` 读取路径来自 `configuration.getEditorConfig()`（仅服务端配置可改，非 HTTP 输入） |
| magic-script 沙箱绕过 | 绕过与否不相关——magic-script **本身设计允许任意 Java**（这是产品功能，不是绕过）；安全边界在认证层而非脚本引擎层 |
| `IpUtils.getRealIP` 信任 `X-Forwarded-For` | 仅用于日志/审计，不影响认证或授权逻辑 |

---

*End of report.*
