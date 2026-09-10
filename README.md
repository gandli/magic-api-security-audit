<p align="center">
  <a href="https://github.com/gandli/magic-api-security-audit">
    <img src="./assets/banner.svg" alt="magic-api Security Audit">
  </a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-v2.2.2-C9D1D9?style=flat-square&labelColor=0D1117" alt="version">
  <img src="https://img.shields.io/badge/findings-9%20%282C%203H%202M%201L%29-C9D1D9?style=flat-square&labelColor=0D1117" alt="findings">
  <img src="https://img.shields.io/badge/status-dynamically%20confirmed-F85149?style=flat-square&labelColor=0D1117" alt="status">
  <img src="https://img.shields.io/badge/license-MIT-C9D1D9?style=flat-square&labelColor=0D1117" alt="license">
  <img src="https://img.shields.io/badge/java-8%2B-C9D1D9?style=flat-square&labelColor=0D1117" alt="java">
</p>

---

> 本仓库收录针对 [magic-api](https://github.com/ssssssss-team/magic-api) v2.2.2 的完整代码审计研究。
> 包含 **9 个可利用漏洞**（2 Critical / 3 High / 2 Medium / 1 Low），全部具备代码级调用链追踪与 HTTP PoC。其中 F-01（未授权 RCE）已在 Docker 复现环境中获得 `uid=0(root)` 命令执行输出。

---

## 目录

- [部署场景对比](#部署场景对比)
- [漏洞列表](#漏洞列表)
- [环境快速开始](#环境快速开始)
- [复现手册](#复现手册)
- [鉴权模式攻击面](#鉴权模式攻击面)
- [仓库结构](#仓库结构)
- [修复建议](#修复建议)
- [贡献者](#贡献者)
- [免责声明](#免责声明)

---

## 部署场景对比

两种部署形态的攻击面差异——**开启鉴权仅修复了 5/9 项**：

| ID | 漏洞 | 默认（无鉴权） | 已开启鉴权 |
|----|------|:---:|:---:|
| F-01 | 未授权 RCE | 🔴 **可直接利用** | 🟢 需 token（但见 F-06） |
| F-02 | JDBC SSRF/RCE | 🔴 **可直接利用** | 🟢 需 token |
| F-03 | 脚本源码泄露 | 🔴 **可直接利用** | 🟢 需 token |
| F-04 | 备份导出/回滚 | 🔴 **可直接利用** | 🟢 需 token |
| F-05 | /push SSRF | 🟡 可利用 | 🟢 需 token |
| F-06 | 静态 MD5 token | ⚪ 不适用（无鉴权时） | 🔴 **密码泄露/猜测即可离线算 token，登出无效** |
| F-07 | receivePush RCE 注入 | 🔴 **可利用（需知道 secret-key）** | 🔴 **仍可利用——@Valid(requireLogin=false) 绕过登录，已知 secret-key 即可注入持久化 RCE 后门** |
| F-08 | CORS 反射 | 🟡 可读响应 | 🔴 **仍可反射任意 Origin（泄露风险）** |
| F-09 | 类路径枚举 | 🔴 **可直接利用** | 🔴 **仍可利用——2298 类 + 8 个 RCE gadget 无 token 可取** |

**结论**：

- **场景 A（默认无鉴权）**：任何能访问 HTTP 端口的攻击者直接获得 RCE（F-01），完整攻击链已动态复现。
- **场景 B（已开启鉴权）**：仅配置 username/password **不足以止血**——攻击者可用 F-07（secret-key 已知时直接未授权 RCE）或 F-06（已知密码离线算 token 后走 F-01 链），并用 F-09 为 RCE 链侦察。场景 B 复现记录见 [AUTH-MODE.md](./reproduction/AUTH-MODE.md)。

---

## 漏洞列表

<table>
  <thead>
    <tr>
      <th align="center">ID</th>
      <th>严重性</th>
      <th>漏洞类型</th>
      <th>CVSS 3.1</th>
      <th>CVE 编号</th>
      <th>动态复现</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td align="center"><strong>F-01</strong></td>
      <td><img src="https://img.shields.io/badge/CRITICAL-red?style=flat-square" alt="CRITICAL"></td>
      <td>未授权远程代码执行 (RCE)</td>
      <td>10.0</td>
      <td>待分配</td>
      <td>✅ 动态确认</td>
    </tr>
    <tr>
      <td align="center"><strong>F-02</strong></td>
      <td><img src="https://img.shields.io/badge/HIGH-orange?style=flat-square" alt="HIGH"></td>
      <td>未授权 JDBC SSRF / JDBC-RCE</td>
      <td>9.1</td>
      <td>待分配</td>
      <td>◐ 接口可达已验</td>
    </tr>
    <tr>
      <td align="center"><strong>F-03</strong></td>
      <td><img src="https://img.shields.io/badge/HIGH-orange?style=flat-square" alt="HIGH"></td>
      <td>未授权脚本源码泄露</td>
      <td>7.5</td>
      <td>待分配</td>
      <td>◐ 接口可达已验</td>
    </tr>
    <tr>
      <td align="center"><strong>F-04</strong></td>
      <td><img src="https://img.shields.io/badge/HIGH-orange?style=flat-square" alt="HIGH"></td>
      <td>未授权备份导出 + 全量回滚</td>
      <td>8.6</td>
      <td>待分配</td>
      <td>◐ 接口可达已验</td>
    </tr>
    <tr>
      <td align="center"><strong>F-05</strong></td>
      <td><img src="https://img.shields.io/badge/MEDIUM-yellow?style=flat-square" alt="MEDIUM"></td>
      <td>服务端请求伪造 (SSRF) via /push</td>
      <td>6.5</td>
      <td>待分配</td>
      <td>◐ 接口可达已验</td>
    </tr>
    <tr>
      <td align="center"><strong>F-06</strong></td>
      <td><img src="https://img.shields.io/badge/MEDIUM-yellow?style=flat-square" alt="MEDIUM"></td>
      <td>静态 MD5 Token / 无效登出</td>
      <td>5.3</td>
      <td>待分配</td>
      <td>◐ 逻辑静态确认</td>
    </tr>
    <tr>
      <td align="center"><strong>F-07</strong></td>
      <td><img src="https://img.shields.io/badge/CRITICAL-red?style=flat-square" alt="CRITICAL"></td>
      <td>receivePush 未授权持久化 RCE（鉴权模式下仍可达）</td>
      <td>9.8</td>
      <td>待分配</td>
      <td>✅ 动态确认（无token注入→uid=0）</td>
    </tr>
    <tr>
      <td align="center"><strong>F-08</strong></td>
      <td><img src="https://img.shields.io/badge/LOW-green?style=flat-square" alt="LOW"></td>
      <td>CORS 反射 Origin + Allow-Credentials</td>
      <td>3.7</td>
      <td>待分配</td>
      <td>✅ 动态确认</td>
    </tr>
    <tr>
      <td align="center"><strong>F-09</strong></td>
      <td><img src="https://img.shields.io/badge/MEDIUM-yellow?style=flat-square" alt="MEDIUM"></td>
      <td>未授权类路径枚举（鉴权模式下仍可达）</td>
      <td>5.3</td>
      <td>待分配</td>
      <td>✅ 动态确认（2298 类 + 8 gadget）</td>
    </tr>
  </tbody>
</table>

---

## 环境快速开始

**前置要求**: Docker 20.10+

```bash
# 克隆仓库
git clone https://github.com/gandli/magic-api-security-audit.git
cd magic-api-security-audit

# 一键构建并启动复现环境 (默认无认证, 服务端口 9999)
bash scripts/build_and_run.sh

# 验证服务就绪
curl -s http://localhost:9999/magic/web/config.json | python3 -m json.tool

# 执行未授权 RCE (F-01)
python3 scripts/exploit_f01_rce.py http://localhost:9999 "id; cat /etc/passwd"
```

**预期输出** (容器内 uid=0 命令执行):

```
[+] groupId: b99755d570ba401c982b8085f5339484
[+] script saved, fileId: 8598433184784a64b41761e665f7e096
[+] RCE output:
uid=0(root) gid=0(root) groups=0(root)
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```

### 关键技术细节

| 要点 | 说明 |
|---|---|
| 工作台 base path | `magic-api.web` 配置值 (本例 `/magic/web`) |
| 保存脚本 body 编码 | `ROT13(Base64(JSON))` |
| magic-script 类引用 | 跨包类必须 `import` (如 `java.lang.ProcessBuilder`) |
| 执行地址 | `{分组path}/{脚本path}` |

---

## 复现手册（场景 A：默认无鉴权）

各漏洞详细复现步骤、请求构造与验证方法见 **[REPRODUCTION.md](./reproduction/REPRODUCTION.md)**，包含:

- 完整 Docker 环境搭建 (Dockerfile + pom.xml + application.properties)
- 9 个漏洞的 curl 构造示例
- F-01 RCE 动态复现记录 (`uid=0` 输出)
- F-07 无token注入zip→RCE 完整链路
- 接口可达性验证（F-02~F-08）

## 鉴权模式攻击面（场景 B：已开启鉴权）

即使配置了 `magic-api.security.username/password`，仍有可利用面，详见 **[AUTH-MODE.md](./reproduction/AUTH-MODE.md)**：

- **F-07 升级（CRITICAL）**: `receivePush` (`/_magic-api-sync`) 使用 `@Valid(requireLogin=false)`，无 token 也能 `mode=full` 全量覆盖工作区并注入任意脚本 → **未授权 RCE，后门重启存活**（`scripts/exploit_f07_push_rce.py`）
- **F-09**: `/classes.txt` + `/classes` 泄露完整 classpath（2298 类，含 8 个 RCE gadget）
- **F-06**: token = `MD5(username\|\|password)` 可离线预计算，`logout` 无吊销效果
- 其余写端点（save/jdbc/push/backups）鉴权后需要 token（HTTP 200 + `code:401`）

---

## 仓库结构

```
magic-api-security-audit/
├── README.md                           # 本文档
├── LICENSE                             # MIT
├── REPORT.md                           # 审计报告 (执行摘要 + 修复建议)
├── architecture.md                     # 代码结构与调用链分析
├── findings.json                       # 结构化漏洞数据 (9 条, 校验通过)
├── FINDINGS-DETAIL.md                  # 9 条漏洞详情 (按严重性降序)
├── reproduction/
│   ├── REPRODUCTION.md                 # 场景A复现手册: 默认无鉴权 (Docker + PoC curl)
│   └── AUTH-MODE.md                    # 场景B复现手册: 已开启鉴权 (F-06/07/08/09)
└── scripts/
    ├── build_and_run.sh                # 一键搭建复现环境
    ├── exploit_f01_rce.py              # F-01 未授权 RCE 利用脚本
    ├── poc_f02_jdbc_ssrf.py            # F-02 JDBC SSRF 探测
    ├── poc_f03_source_disclosure.py    # F-03 源码泄露
    ├── poc_f04_backup.py               # F-04 备份导出/回滚 (回滚需 --rollback)
    ├── poc_f05_push_ssrf.py            # F-05 /push SSRF
    ├── poc_f06_static_token.py         # F-06 静态 MD5 token / 登出无效
    ├── poc_f07_sign_replay.py          # F-07 receivePush 签名重放
    ├── exploit_f07_push_rce.py          # F-07 完整利用链: 无token RCE (鉴权后仍可用)
    ├── poc_f08_cors.sh                 # F-08 CORS 反射验证
    └── poc_f09_classpath_enum.py       # F-09 类路径枚举 (鉴权后仍可达)
```

---

## 根因 (一行)

`DefaultAuthorizationInterceptor.requireLogin()` 默认 `false`；`MagicWebRequestInterceptor.handle` 对 `@Valid`-less 控制器跳过 token 校验；`allowVisit` 默认 `true` → 无认证即可访问全部管理端点。

---

## 修复建议

**紧急 (F-01)**:
拒绝注册工作台写端点，或在未配置 `magic-api.security.username/password` 时强制 `requireLogin=true` 并输出 `WARN` 日志。

**高优先级 (F-02~F-04)**:
- `/datasource/jdbc/test`: 增加 `@Valid` + 连接串白名单 (host/port)
- `/resource/file/{id}`: 拒绝无认证访问
- `/backup/rollback`: 禁止 `id=full` 的无认证回滚

**中优先级 (F-05~F-07)**:
- `/push`: 禁用反射型 SSRF，限制推送目标白名单
- token: 替换为 JWT/随机 UUID + TTL + refreshToken
- receivePush: sign 中加入 `±300s` 时间窗口校验

**统一方案**:
`allowVisit` 默认改为拒绝 (deny-by-default)；接口权限按操作粒度配置。

---

## 贡献者

<a href="https://github.com/gandli">
  <img src="https://github.com/gandli.png" width="50" height="50" style="border-radius:50%" alt="gandli">
</a>

---

## 免责声明

本研究仅供安全研究与防御参考。所有漏洞均已在本地隔离环境复现，不含任何生产数据。使用者须遵守当地法律法规，未经授权不得对目标系统进行测试。

---

<p align="center">
  <sub>由 <a href="https://github.com/gandli">gandli</a> 使用 <a href="https://github.com/oil-oil/beautify-github-readme">beautify-github-readme</a> 排版</sub>
</p>
