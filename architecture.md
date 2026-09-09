# Architecture Summary — magic-api v2.2.2

**Repo:** https://github.com/ssssssss-team/magic-api
**Commit audited:** `master` (depth-1 clone)
**Stack:** Java 17 (build), Spring Boot 2.4.5, Spring MVC. Modules: `magic-api` (core), `magic-api-spring-boot-starter`, `magic-editor` (bundled Vue UI), `magic-api-plugins` (redis/cluster/notify/websocket/spring-cache).
**Audit mode:** single-agent (no Task/subagent primitives available). Recon (Phase 1), Hunt (Phase 2), Validate (Phase 3) performed inline by reading source; Phase 6 independent verification performed by re-reading the same call sites and confirming there is no compensating control.

> Note on prior runs: this is run-1; no prior `findings.json` exists, so no cross-run reconciliation was needed.

## What the product is
magic-api is a "low-code" backend: a web console where a user authors **magic-script** API endpoints that are persisted and executed server-side. magic-script is a full scripting language (`magic-script` 1.9.0) that resolves `java.lang.*` and `java.util.*` by default and can `import` and `new` **any** Java class (verified in `MagicResourceLoader`: `addPackage("java.lang.*")`, `addPackage("java.util.*")`, `Class.forName` via a configurable classloader). **Executing a magic-script is therefore equivalent to executing arbitrary Java.** This is the root enabler for the most severe finding.

## Request flow (the security-critical path)
```
HTTP → MagicRequestContextFilter / MagicWebRequestInterceptor
        → AuthorizationInterceptor.requireLogin()  and  allowVisit(...)
        → @Valid(requireLogin=, authorization=, readonly=)  [on controller method]
        → controller method
```
Key interceptor logic (`MagicWebRequestInterceptor.handle`):
```java
boolean validRequiredLogin = (valid == null || valid.requireLogin()); // @Valid present & requireLogin=true ⇒ true
boolean requiredLogin      = authorizationInterceptor.requireLogin();  // DefaultAuthorizationInterceptor
if (validRequiredLogin && requiredLogin) {
    if (token invalid) return 401;
}
doValid(request, valid);   // when valid==null, returns immediately (only checks readonly)
```
`DefaultAuthorizationInterceptor` constructor:
```java
this.requireLogin = username != null && password != null;   // both null by DEFAULT ⇒ false
```
- **Default (`magic-api.security.username/password` unset):** `requireLogin()` returns `false` → every workbench endpoint skips the login check. For methods *without* `@Valid`, `doValid(request, null)` does nothing at all. For methods *with* `@Valid` (requireLogin=false such as `/config.json`, `/classes`, `/login`, `/push`/`receivePush`), the login skip still applies and `allowVisit` defaults to `true`.
- **When auth is configured:** `requireLogin()` → `true`, so a valid token is required for endpoints whose `@Valid.requireLogin()` is true. **However** many sensitive endpoints (`/datasource/jdbc/test`, all `/backup*`, all `/resource*`) carry **no `@Valid`** and never call `allowVisit` with a restrictive authorization, so they are reached after only a *login* check — i.e. any authenticated user, regardless of role.

`allowVisit`/`doValid` in `MagicController`:
```java
protected boolean allowVisit(MagicHttpServletRequest request, Authorization authorization, MagicEntity... entities) {
    if (readonly && authorization != READONLY && authorization != READONLY_...) return false;
    return configuration.getAuthorizationInterceptor().allowVisit(magicUser, request, authorization, entities);
}
```
`DefaultAuthorizationInterceptor.allowVisit` (no override) **returns `true`** — meaning the `@Valid(authorization=...)` values (VIEW/SAVE/DELETE/BACKUP/PUSH/UPLOAD…) are **advisory only**; the default interceptor enforces *none* of them. The only default-enforced thing is login (when credentials are set). All role separation is the integrator's responsibility and is off by default.

## Endpoints of interest (registered in `MagicAPIAutoConfiguration`, only if `magic-api.web` is set)
| Path | Controller | `@Valid`? | `allowVisit` called? | Visible by default |
|------|-----------|----------|----------------------|--------------------|
| `/` (UI) | MagicWorkbenchController | requireLogin=false | no | **yes (unauth)** |
| `/config.json`, `/classes`, `/classes.txt` | MagicWorkbenchController | requireLogin=false | no | **yes (unauth)** |
| `/resource/file/{folder}/save`, `/resource/file/{id}`, `/resource/delete`, `/resource/folder/...`, `/search` | MagicResourceController | **none** | yes (allowVisit→true) | **yes (unauth)** |
| `/datasource/jdbc/test` | MagicDataSourceController | **none** | no | **yes (unauth)** |
| `/backups`, `/backup/{id}`, `/backup`, `/backup/rollback` | MagicBackupController | **none** | no | **yes (unauth)** |
| `/upload`, `/download` | MagicWorkbenchController | readonly=false, authorization=UPLOAD | yes (allowVisit→true) | **yes (unauth)** |
| `/push` | MagicWorkbenchController | authorization=PUSH | yes (allowVisit→true) | **yes (unauth)** |
| `/{id}` (saved API execution) | RequestHandler | n/a | n/a | yes (this is the product) |
| `/_magic-api-sync` (`receivePush`) | MagicWorkbenchController | requireLogin=false | no | only if `secretKey` set |

## Persistence / execution internals
- Saved scripts, groups, options persist either to **DB** (`DatabaseResource`) or local **files** (`FileResource`) depending on `magic-api.resource.*`. Both store the raw script text.
- Scripts run through `org.ssssssss.script.MagicScript.create(...).execute(ctx)` → full Java access (see above).
- `/datasource/jdbc/test` → `JdbcUtils.getConnection(driver, url, user, pass)` → `Class.forName(driver)` + `DriverManager.getConnection(url, …)`. Fully attacker-controlled driver/url.
- `/push` → `RestTemplate.postForObject(target, …)` where `target` = `magic-push-target` header (attacker-controlled).
- `/receivePush` (only mounted when `secretKey` non-blank): signature `MD5(timestamp|mode|MD5(bytes)|secretKey)` via `SignUtils.sign`; **no timestamp-freshness check**; `mode=FULL` wipes the workspace and replaces it with pushed content.
- Login (`/login`): token = `MD5(username + "||" + password)`, returned in `Magic-Token` response header; `logout()` is a **no-op**; `refreshToken` is a no-op; token never expires.
- CORS (`MagicCorsFilter`): reflects `Origin` header into `Access-Control-Allow-Origin` and sets `Access-Control-Allow-Credentials: true` for workbench paths. Token is a header (`Magic-Token`), not a cookie, which limits cookie-CSRF but enables cross-origin *reads* of the (by-default) unauthenticated surface and aids token theft by a malicious page that can already drive a login.

## Severity model used (per skill)
CRITICAL = unauthenticated RCE / full data compromise; HIGH = authenticated RCE, auth bypass, secret/SSRF→RCE, stored XSS with real impact; MEDIUM = targeted SSRF, replay, weak-but-not-broken auth, cross-origin reads; LOW = defense-in-depth gaps with no standalone exploit. Only findings with a concrete, reproducible attack path are reported; items that are theoretical or integrator-config-dependent are listed as hardening notes, not findings.
