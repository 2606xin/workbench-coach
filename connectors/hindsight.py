#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Hindsight 活动记录读取器（v2 数据源 · 安检通过后接入）

Hindsight（GPL-3，https://github.com/Tomotsugu-dev/Hindsight）是本地优先的
桌面活动追踪应用。按 v2 设计：不集成其代码（GPL），只读它落在本机的
sqlite 数据文件——数据接口不受协议传染。安检结论（2026-11-11 实测）：
默认截屏/OCR 关、云同步关、无对外连接、无监听端口、开发者签名有效。

用法：
  python3 connectors/hindsight.py                    # 汇总今天
  python3 connectors/hindsight.py --days 3           # 最近 3 天
  python3 connectors/hindsight.py --since 2026-11-11T00:00:00
  python3 connectors/hindsight.py --inbox            # 写进工作台收集箱（下次 collect 自动进素材包）

设计：
- 数据库先整体复制到临时目录再读（WAL 活跃库安全，且绝不影响 Hindsight 自身）；
- 窗口标题按 workbench.py 的 Redactor 脱敏（标题里可能有密钥/手机号）；
- 只输出聚合结果（应用/分类的分钟数 + 高频窗口标题），不导出逐秒明细。
只用 Python 标准库。
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
from workbench import Redactor, parse_time  # noqa: E402  复用同一套脱敏与时间解析

DB = Path.home() / "Library/Application Support/Hindsight/hindsight.sqlite"


def load_rows(since: dt.datetime | None):
    tmp = Path(tempfile.mkdtemp(prefix="qj_hs_"))
    try:
        local = tmp / "hindsight.sqlite"
        shutil.copy2(DB, local)
        for ext in ("-wal", "-shm"):
            src = Path(str(DB) + ext)
            if src.exists():
                shutil.copy2(src, tmp / (local.name + ext))
        con = sqlite3.connect(f"file:{local}?mode=ro", uri=True)
        rows = con.execute("SELECT started_at, duration_secs, process_name, window_title, category_id, url_host "
                           "FROM activities WHERE excluded=0 AND (? IS NULL OR started_at > ?)",
                           (since.isoformat() if since else None, since.isoformat() if since else None)).fetchall()
        cats = dict(con.execute("SELECT id, name FROM categories")) if [
            r for r in con.execute("SELECT name FROM sqlite_master WHERE name='categories'")] else {}
        con.close()
        return rows, cats
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def digest(rows, cats, red) -> dict:
    by_app, by_cat, titles = {}, {}, {}
    total = 0
    for started, dur, proc, title, cat, host in rows:
        d = int(dur or 0)
        total += d
        by_app[proc] = by_app.get(proc, 0) + d
        by_cat[cats.get(cat, cat or "未分类")] = by_cat.get(cats.get(cat, cat or "未分类"), 0) + d
        label = red((title or "").strip())[:60]
        if label:
            k = (proc, label)
            titles[k] = titles.get(k, 0) + d
    mm = lambda s: round(s / 60)
    return {
        "total_min": mm(total),
        "apps": sorted(([mm(v), k] for k, v in by_app.items()), reverse=True)[:12],
        "categories": sorted(([mm(v), k] for k, v in by_cat.items()), reverse=True)[:8],
        "titles": sorted(([mm(v), k[0], k[1]] for k, v in titles.items()), reverse=True)[:15],
    }


def to_markdown(d: dict, span: str, day: str) -> str:
    lines = [f"# 活动记录 · {span}", "",
             f"> 来源：Hindsight 本地库（已脱敏）；总计 {d['total_min']} 分钟。生成于 {day}。", ""]
    lines += ["## 按应用（分钟）", ""] + [f"- {k}：{v}" for v, k in d["apps"]] + [""]
    lines += ["## 按分类（分钟）", ""] + [f"- {k}：{v}" for v, k in d["categories"]] + [""]
    lines += ["## 高频窗口", ""] + [f"- [{a}] {t}（{v} 分钟）" for v, a, t in d["titles"]]
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=1)
    ap.add_argument("--since")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--inbox", action="store_true", help="写进 ~/清见工作台/收集箱/")
    ap.add_argument("--home", default=str(Path.home()))
    a = ap.parse_args()

    if not DB.exists():
        sys.exit("未找到 Hindsight 数据库（还没安装或没运行过？路径：" + str(DB) + "）")
    since = parse_time(a.since) if a.since else dt.datetime.now().replace(hour=0, minute=0, second=0, tzinfo=dt.timezone.utc) - dt.timedelta(days=a.days - 1)
    red = Redactor(Path(a.home).expanduser())
    rows, cats = load_rows(since)
    if not rows:
        print(f"{since:%Y-%m-%d %H:%M} 以来没有活动记录（刚装的话正常，让它先跑一会儿）")
        return 0
    d = digest(rows, cats, red)
    day = dt.date.today().isoformat()
    span = f"{since:%m-%d %H:%M} 起"
    if a.json:
        print(json.dumps(d, ensure_ascii=False, indent=1))
    else:
        print(to_markdown(d, span, day))
    if a.inbox:
        out = Path.home() / "清见工作台/收集箱"
        out.mkdir(parents=True, exist_ok=True)
        f = out / f"活动记录_{day}.md"
        f.write_text(to_markdown(d, span, day), encoding="utf-8")
        print(f"已写入收集箱：{f}")


if __name__ == "__main__":
    main()
