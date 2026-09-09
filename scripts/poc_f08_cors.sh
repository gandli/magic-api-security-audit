#!/usr/bin/env bash
# F-08: CORS 反射 Origin + Allow-Credentials (magic-api v2.2.2)
# MagicCorsFilter 无条件回显 Origin 并附带 Access-Control-Allow-Credentials: true
# 浏览器侧 fetch(credentials:'include') 可读默认无认证工作台数据 (若配置认证/token 存 cookie 则更危险)
set -e
TARGET="${1:-http://localhost:9999}/magic/web/config.json"
ORIGIN="${2:-http://evil.example}"
echo "[+] 探测 $TARGET (Origin: $ORIGIN)"
curl -s -D - -o /dev/null -H "Origin: $ORIGIN" "$TARGET" \
  | grep -iE "access-control-allow-origin|access-control-allow-credentials|access-control-expose-headers" \
  || echo "[!] 未返回 CORS 头"
