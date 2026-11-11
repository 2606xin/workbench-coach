#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""清见 · 个人工作台 —— 本地 AI 会话收集器（workbench-coach 的底层脚本）

把散落在各个 AI 工具里的本地会话，脱敏后放进同一个上下文。
只用 Python 标准库（3.8+），Windows / macOS / Linux 通用，不联网、不上传。

子命令：
  detect    看看这台电脑上有哪些 AI 工具的本地会话（只统计，不输出内容）
  connect   接入官方通道（v2）：connect feishu —— 检测 lark-cli 授权、写入 scope，之后 collect 自动拉飞书群消息
  discover  在常见目录里找「可能是会话记录」的文件，给新工具做适配用（只列文件名和大小）
  pick      打开本地页面：显示 AI 的落地分析，选择数据源（AI 会话 / 文件夹 / 收集箱）和触发器，并确认授权
  collect   按选择范围收集 → 脱敏 → 生成「素材包」；首次建基线，之后按游标增量
  build     按方案和选择，生成用户自己的工作台技能（SKILL.md）、输出模板和触发器设置说明
  feedback  反馈环：记下「好」或修改意见（写进 偏好.md，下次生成时遵守）；--review 汇总复盘
  page      工作台主页：把每次的结果、偏好和运行状态汇总成 工作台数据.js，并检查主页没有外部资源
  push      把一份结果推送到企业微信群（地址只读环境变量 WECOM_WEBHOOK）
  import    后路：把手动导出的 .md / .txt / .json / .jsonl 放进来，同样脱敏
  redact    对任意文本文件做脱敏（也可用来自检：redact --self-test）

常用：
  python3 workbench.py detect
  python3 workbench.py pick                 # 浏览器里勾选范围并确认
  python3 workbench.py collect              # 按刚才的选择收集
  python3 workbench.py collect              # 以后每天再跑一次 = 增量

参数 --home 可以指向别的「家目录」（用示例数据彩排：--home ../示例输入/home）。
参数 --out  是工作台目录，默认 ~/清见工作台。
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import html
import json
import os
import re
import secrets
import shutil
import sqlite3
import sys
import tempfile
import threading
import webbrowser
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

VERSION = "0.1.0"
UTC = dt.timezone.utc

# ---------------------------------------------------------------- 脱敏 ----
# 每条规则：(类型名, 正则, 可选校验函数)。命中后替换为【已遮挡·类型】。
# 规则宁可多遮，不可漏遮；新规则加在这里即可。


def _luhn(s: str) -> bool:
    d = [int(c) for c in re.sub(r"\D", "", s)]
    if not 15 <= len(d) <= 19:
        return False
    total = 0
    for i, n in enumerate(reversed(d)):
        if i % 2:
            n *= 2
            n -= 9 if n > 9 else 0
        total += n
    return total % 10 == 0


def _cn_id(s: str) -> bool:
    s = s.upper()
    if not re.fullmatch(r"\d{17}[\dX]", s):
        return False
    w = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
    code = "10X98765432"
    return code[sum(int(a) * b for a, b in zip(s[:17], w)) % 11] == s[17]


REDACT_RULES = [
    ("私钥", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----"), None),
    ("Anthropic密钥", re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}"), None),
    ("OpenAI类密钥", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}"), None),
    ("GitHub令牌", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}"), None),
    ("AWS密钥", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), None),
    ("阿里云AccessKey", re.compile(r"\bLTAI[A-Za-z0-9]{12,24}\b"), None),
    ("Google密钥", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), None),
    ("Slack令牌", re.compile(r"\bxox[abpors]-[A-Za-z0-9\-]{10,}"), None),
    ("企微机器人key", re.compile(r"(qyapi\.weixin\.qq\.com/cgi-bin/webhook/send\?key=)[A-Za-z0-9\-]+"), None),
    ("飞书/钉钉Webhook", re.compile(r"https://(?:open\.feishu\.cn/open-apis/bot/v2/hook|oapi\.dingtalk\.com/robot/send\?access_token=)[A-Za-z0-9\-=]+"), None),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"), None),
    ("Bearer令牌", re.compile(r"(?i)(bearer\s+)[A-Za-z0-9_\-\.=]{16,}"), None),
    ("密码/密钥赋值", re.compile(
        r"(?i)((?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|密码|口令|密钥)\s*[:=：]\s*[\"']?)[^\s\"'，。,;；【]{4,}"), None),
    ("连接串", re.compile(r"\b[a-z][a-z0-9+]*://[^\s:/@]+:[^\s@/]+@[^\s/]+"), None),
    ("身份证号", re.compile(r"(?<!\d)\d{17}[\dXx](?!\d)"), _cn_id),
    ("银行卡号", re.compile(r"(?<!\d)(?:\d[ -]?){15,18}\d(?!\d)"), _luhn),
    ("手机号", re.compile(r"(?<!\d)(?:\+?86[- ]?)?1[3-9]\d{9}(?!\d)"), None),
    ("邮箱", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"), None),
]


class Redactor:
    def __init__(self, home: Path | None = None):
        self.counts: dict[str, int] = defaultdict(int)
        self.home = str(home) if home else None

    def __call__(self, text: str) -> str:
        if not text:
            return text
        for name, rx, check in REDACT_RULES:
            def repl(m, name=name, check=check):
                whole = m.group(0)
                if check and not check(whole):
                    return whole
                self.counts[name] += 1
                # 保留前缀（如 "password=" "Bearer " "key="），只遮值
                if m.lastindex and m.group(1) and whole.startswith(m.group(1)):
                    return m.group(1) + f"【已遮挡·{name}】"
                return f"【已遮挡·{name}】"
            text = rx.sub(repl, text)
        return text

    def path(self, p: str) -> str:
        """路径里的用户名换成 ~，避免泄露电脑用户名。"""
        if not p:
            return p
        if self.home and p.startswith(self.home):
            p = "~" + p[len(self.home):]
        p = re.sub(r"(?i)^([a-z]:\\users\\)[^\\]+", r"\1~", p)
        p = re.sub(r"^/(Users|home)/[^/]+", "~", p)
        return p.replace("\\", "/")

    def report(self) -> str:
        if not self.counts:
            return "未发现需要遮挡的敏感信息。"
        return "；".join(f"{k} {v} 处" for k, v in sorted(self.counts.items(), key=lambda x: -x[1]))


# ------------------------------------------------------------ 通用解析 ----
SKIP_PREFIXES = (
    "<environment_context>", "<user_instructions>", "<command-name>", "<command-message>",
    "<local-command-stdout>", "<system-reminder>", "Caveat:", "# AGENTS.md", "<permissions",
)


def parse_time(v) -> dt.datetime | None:
    if v is None or v == "":
        return None
    try:
        if isinstance(v, (int, float)) or (isinstance(v, str) and re.fullmatch(r"\d{10,13}(\.\d+)?", v)):
            x = float(v)
            if x > 1e12:
                x /= 1000.0
            return dt.datetime.fromtimestamp(x, UTC)
        s = str(v).strip().replace("Z", "+00:00")
        t = dt.datetime.fromisoformat(s[:32]) if "T" in s or "-" in s else None
        if t and t.tzinfo is None:
            t = t.replace(tzinfo=UTC)
        return t
    except (ValueError, OverflowError, OSError):
        return None


def text_of(content) -> str:
    """从各种 content 结构里拿出纯文本（跳过工具调用结果和图片）。"""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, dict):
        t = content.get("type", "")
        if t in ("tool_result", "tool_use", "function_call", "function_call_output", "image", "input_image", "thinking", "reasoning"):
            return ""
        for k in ("text", "content", "message", "parts", "value"):
            if k in content:
                return text_of(content[k])
        return ""
    if isinstance(content, list):
        return "\n".join(x for x in (text_of(c) for c in content) if x)
    return ""


def clean(text: str) -> str:
    text = (text or "").strip()
    if not text or text.startswith(SKIP_PREFIXES):
        return ""
    return text


class Msg:
    __slots__ = ("tool", "session", "project", "ts", "role", "text", "file", "who")

    def __init__(self, tool, session, project, ts, role, text, file, who=None):
        self.tool, self.session, self.project = tool, session, project
        self.ts, self.role, self.text, self.file = ts, role, text, file
        self.who = who  # 发言者名字（飞书等外部通道用；AI 会话不设）


def generic_obj(obj: dict):
    """尽量从一行 JSON 里猜出 (role, text, ts, cwd, session)。"""
    if not isinstance(obj, dict):
        return None
    inner = obj.get("message") if isinstance(obj.get("message"), dict) else obj.get("payload") if isinstance(obj.get("payload"), dict) else obj
    role = inner.get("role") or obj.get("role") or obj.get("type") or inner.get("sender") or inner.get("author")
    if isinstance(role, dict):
        role = role.get("role")
    role = str(role or "").lower()
    if role in ("human", "user", "user_message"):
        role = "user"
    elif role in ("assistant", "ai", "model", "bot", "agent_message"):
        role = "assistant"
    else:
        return None
    text = text_of(inner.get("content") if "content" in inner else inner.get("text") or inner.get("message"))
    ts = parse_time(obj.get("timestamp") or obj.get("created_at") or obj.get("time") or inner.get("timestamp") or inner.get("create_time"))
    cwd = obj.get("cwd") or inner.get("cwd") or obj.get("workspace") or ""
    sid = obj.get("sessionId") or obj.get("session_id") or obj.get("conversation_id") or ""
    return role, text, ts, cwd, sid


def read_jsonl(path: Path):
    try:
        with path.open(encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue
    except OSError:
        return


def fmtime(path: Path) -> dt.datetime:
    try:
        return dt.datetime.fromtimestamp(path.stat().st_mtime, UTC)
    except OSError:
        return dt.datetime.now(UTC)


# --------------------------------------------------------------- 适配器 ----
# 每个工具：候选根目录（按顺序找第一个存在的）+ 解析函数。
# 新工具实测后在这里加一项；找不到路径时先用 discover 子命令。


def parse_codex(path: Path, tool: str):
    sid, cwd, seen = path.stem, "", set()
    for o in read_jsonl(path):
        t, p = o.get("type"), o.get("payload") or {}
        if t == "session_meta":
            sid = p.get("id") or sid
            cwd = p.get("cwd") or cwd
            continue
        if t == "turn_context" and p.get("cwd"):
            cwd = p["cwd"]
        role, text = None, ""
        if t == "response_item" and p.get("type") == "message":
            role, text = p.get("role"), text_of(p.get("content"))
        elif t == "event_msg" and p.get("type") in ("user_message", "agent_message"):
            role = "user" if p["type"] == "user_message" else "assistant"
            text = p.get("message") or ""
        elif t is None and o.get("role"):  # 旧版格式
            role, text = o.get("role"), text_of(o.get("content"))
        if role not in ("user", "assistant"):
            continue
        text = clean(text)
        key = (role, text[:200])
        if not text or key in seen:
            continue
        seen.add(key)
        yield Msg(tool, sid, cwd, parse_time(o.get("timestamp")) or fmtime(path), role, text, str(path))


def parse_claude_like(path: Path, tool: str):
    msgs = list(_parse_claude_like(path, tool))
    cwds = [m.project for m in msgs if m.project]
    if cwds:
        main_cwd = max(set(cwds), key=cwds.count)
        for m in msgs:
            m.project = m.project or main_cwd
    return msgs


def _parse_claude_like(path: Path, tool: str):
    sid = path.stem
    for o in read_jsonl(path):
        if o.get("isMeta") or o.get("isSidechain"):
            continue
        t = o.get("type")
        if t in ("user", "assistant") and isinstance(o.get("message"), dict):
            m = o["message"]
            c = m.get("content")
            if isinstance(c, list) and any(isinstance(x, dict) and x.get("type") == "tool_result" for x in c):
                continue
            text = clean(text_of(c))
            if text:
                yield Msg(tool, o.get("sessionId") or sid, o.get("cwd") or "", parse_time(o.get("timestamp")) or fmtime(path), t, text, str(path))
            continue
        g = generic_obj(o)
        if g:
            role, text, ts, cwd, s = g
            text = clean(text)
            if text:
                yield Msg(tool, s or sid, cwd, ts or fmtime(path), role, text, str(path))


def parse_json_file(path: Path, tool: str):
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return
    items = data
    if isinstance(data, dict):
        for k in ("messages", "history", "conversation", "items", "turns", "chat"):
            if isinstance(data.get(k), list):
                items = data[k]
                break
    if not isinstance(items, list):
        return
    for o in items:
        g = generic_obj(o) if isinstance(o, dict) else None
        if g:
            role, text, ts, cwd, s = g
            text = clean(text)
            if text:
                yield Msg(tool, s or path.stem, cwd, ts or fmtime(path), role, text, str(path))


TEXT_COLS = ("content", "text", "message", "body", "parts", "data", "payload", "prompt", "query")
ROLE_COLS = ("role", "type", "sender", "author", "message_type", "kind")
TIME_COLS = ("created_at", "timestamp", "time", "ts", "create_time", "created", "updated_at", "date")
SID_COLS = ("session_id", "conversation_id", "thread_id", "chat_id", "task_id", "sessionid")
CWD_COLS = ("cwd", "workspace", "project_path", "workdir", "directory", "path")


def parse_sqlite(path: Path, tool: str):
    """不认识表结构也能读：找「有文本列」的表，按列名猜角色、时间、会话。复制一份再读，不锁原库。"""
    tmp = Path(tempfile.mkdtemp(prefix="qj_")) / "db.sqlite"
    try:
        shutil.copy2(path, tmp)
        for ext in ("-wal", "-shm"):
            if Path(str(path) + ext).exists():
                shutil.copy2(str(path) + ext, str(tmp) + ext)
        con = sqlite3.connect(f"file:{tmp}?mode=ro", uri=True)
        con.row_factory = sqlite3.Row
        tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        sess_cwd = {}
        for tb in tables:
            cols = {r[1].lower(): r[1] for r in con.execute(f'PRAGMA table_info("{tb}")')}
            idc = cols.get("id") or next((cols[c] for c in SID_COLS if c in cols), None)
            cc = next((cols[c] for c in CWD_COLS if c in cols), None)
            if idc and cc:
                try:
                    for r in con.execute(f'SELECT "{idc}", "{cc}" FROM "{tb}"'):
                        if r[1]:
                            sess_cwd[str(r[0])] = str(r[1])
                except sqlite3.DatabaseError:
                    pass
        for tb in tables:
            cols = [r[1] for r in con.execute(f'PRAGMA table_info("{tb}")')]
            low = {c.lower(): c for c in cols}
            tcol = next((low[c] for c in TEXT_COLS if c in low), None)
            if not tcol:
                continue
            rcol = next((low[c] for c in ROLE_COLS if c in low), None)
            mcol = next((low[c] for c in TIME_COLS if c in low), None)
            scol = next((low[c] for c in SID_COLS if c in low), None)
            ccol = next((low[c] for c in CWD_COLS if c in low), None)
            try:
                rows = con.execute(f'SELECT * FROM "{tb}" LIMIT 200000')
            except sqlite3.DatabaseError:
                continue
            for r in rows:
                raw = r[tcol]
                if isinstance(raw, bytes):
                    raw = raw.decode("utf-8", "replace")
                role, text = (str(r[rcol]).lower() if rcol and r[rcol] is not None else ""), ""
                if isinstance(raw, str) and raw[:1] in "[{":
                    try:
                        obj = json.loads(raw)
                        g = generic_obj(obj) if isinstance(obj, dict) else None
                        if g:
                            role, text = g[0], g[1]
                        else:
                            text = text_of(obj)
                    except json.JSONDecodeError:
                        text = raw
                else:
                    text = raw if isinstance(raw, str) else ""
                role = "user" if role in ("user", "human", "user_message") else "assistant" if role in ("assistant", "ai", "model", "bot") else role
                if role not in ("user", "assistant"):
                    continue
                text = clean(text)
                if text:
                    sid = str(r[scol]) if scol else tb
                    yield Msg(tool, sid, str(r[ccol]) if ccol and r[ccol] else sess_cwd.get(sid, ""),
                              (parse_time(r[mcol]) if mcol else None) or fmtime(path), role, text, str(path))
        con.close()
    except (OSError, sqlite3.DatabaseError):
        return
    finally:
        shutil.rmtree(tmp.parent, ignore_errors=True)


def _env(name: str) -> list[Path]:
    v = os.environ.get(name)
    return [Path(v)] if v else []


def source_table(home: Path):
    appdata = Path(os.environ.get("APPDATA", home / "AppData" / "Roaming"))
    return [
        # (工具名, 候选根目录, glob 模式, 解析函数)
        ("Codex", _env("CODEX_HOME") + [home / ".codex"], ["sessions/**/*.jsonl", "archived_sessions/*.jsonl"], parse_codex),
        ("Claude Code", _env("CLAUDE_CONFIG_DIR") + [home / ".claude"], ["projects/*/*.jsonl"], parse_claude_like),
        ("WorkBuddy", [home / ".workbuddy", home / ".workbuddy-ai"], ["projects/**/*.jsonl"], parse_claude_like),
        ("CodeBuddy", [home / ".codebuddy"], ["projects/**/*.jsonl"], parse_claude_like),
        ("ZCode", [home / ".zcode"], ["cli/db/db.sqlite", "cli/**/*.sqlite", "cli/**/*.db"], parse_sqlite),
        ("Kimi", _env("KIMI_SHARE_DIR") + [home / ".kimi"], ["**/*.jsonl"], parse_claude_like),
        ("Gemini CLI", [home / ".gemini"], ["tmp/*/chats/*.json"], parse_json_file),
        ("Qwen Code", [home / ".qwen"], ["**/*.jsonl"], parse_claude_like),
        ("OpenCode", _env("XDG_DATA_HOME") + [home / ".local/share/opencode", appdata / "opencode"], ["**/*.db", "**/*.sqlite"], parse_sqlite),
    ]


def iter_sources(home: Path, only: set[str] | None = None):
    """返回 (工具名, 文件, 解析函数)。同一个文件只出现一次。"""
    seen = set()
    for tool, roots, globs, fn in source_table(home):
        if only and tool not in only:
            continue
        for root in roots:
            if not root.is_dir():
                continue
            for g in globs:
                for f in sorted(root.glob(g)):
                    if f.is_file() and f not in seen:
                        seen.add(f)
                        yield tool, f, fn
            break  # 用第一个存在的根目录


def load_all_builtin(home: Path, only: set[str] | None = None):
    msgs = []
    for tool, f, fn in iter_sources(home, only):
        msgs.extend(fn(f, tool))
    return msgs


# --------------------------------------------------- agent-dump 收集引擎 ----
# 主引擎：开源项目 agent-dump（MIT，https://github.com/xingkaixin/agent-dump）。
# 它负责读取各工具的本地会话（含 ZCode、Kimi、Qoder CN、DSH、Cherry Studio 等），
# 并统一成同一种 JSON；本脚本只负责范围、脱敏、游标和素材包。
# 安装：pip install agent-dump（或 uv tool install agent-dump / scoop / brew / npx @agent-dump/cli）
# agent-dump 不支持的工具（目前是 WorkBuddy、CodeBuddy），继续用内置解析补上。

AD_NAMES = {
    "codex": "Codex", "claudecode": "Claude Code", "zcode": "ZCode", "kimi": "Kimi", "kimi-code": "Kimi Code",
    "qoder": "Qoder", "qoder-cn": "Qoder CN", "cursor": "Cursor", "droid": "Droid", "grok": "Grok", "pi": "Pi",
    "omp": "oh-my-pi", "gemini-cli": "Gemini CLI", "dsh": "DSH", "deepchat": "DeepChat", "cherry": "Cherry Studio",
    "minimax": "MiniMax Code", "antigravity-cli": "Antigravity CLI", "opencode": "OpenCode",
}
BUILTIN_ONLY = {"WorkBuddy", "CodeBuddy"}  # agent-dump 暂不支持，用内置解析
ENGINE = {"name": "auto", "notes": []}


def ad_bin() -> str | None:
    if ENGINE["name"] == "builtin":
        return None
    return shutil.which("agent-dump")


def _ad_env(home: Path) -> dict:
    env = dict(os.environ)
    if str(home) != str(Path.home()):  # 彩排：把示例数据当作家目录
        env.update(HOME=str(home), USERPROFILE=str(home))
        for k in ("CODEX_HOME", "CLAUDE_CONFIG_DIR", "KIMI_SHARE_DIR", "XDG_DATA_HOME"):
            env.pop(k, None)
    return env


def _ad_run(home: Path, args: list[str], timeout=180):
    import subprocess
    r = subprocess.run([ad_bin()] + args, capture_output=True, text=True, encoding="utf-8",
                       errors="replace", env=_ad_env(home), timeout=timeout)
    return r.returncode, r.stdout, r.stderr


def ad_list(home: Path, days: int = 3650) -> list[dict]:
    code, out, err = _ad_run(home, ["--list", "--days", str(days), "--json"])
    try:
        d = json.loads(out)
    except json.JSONDecodeError:
        ENGINE["notes"].append(f"agent-dump 列表失败：{(err or out)[:200]}")
        return []
    for fp in d.get("failed_providers") or []:
        ENGINE["notes"].append(f"agent-dump 读取 {fp.get('provider', fp) if isinstance(fp, dict) else fp} 时出错，已跳过")
    return d.get("data") or []


def _ad_keep(s: dict, only: set[str] | None, projects: set[str] | None,
             full_tools: set[str] | None) -> bool:
    """一个 agent-dump 列表项要不要导出：工具在勾选范围里，且（按项目勾选时）项目也在。
    判定与 in_scope 对齐，最终仍由 in_scope 兜底，个别口径出入只会多导/少导，不影响正确性。"""
    tool = AD_NAMES.get(s.get("provider", ""), s.get("provider", "其他"))
    if only and tool not in only:
        return False
    if projects is not None and tool not in (full_tools or ()):
        if f"{tool}::{s.get('working_directory') or ''}" not in projects:
            return False
    return True


def ad_load(home: Path, only: set[str] | None = None, days: int = 3650,
            projects: set[str] | None = None, full_tools: set[str] | None = None,
            since: dt.datetime | None = None) -> list[Msg]:
    """projects（“工具::项目路径” 集合）给定时，先用列表里的 working_directory 过滤再导出，
    免得勾了具体项目还得把整个工具的会话全导一遍；full_tools 是整体勾选的工具，其会话不过滤；
    since 给定时跳过这之前就没更新过的会话（增量、超限裁剪都靠它，只影响导出哪些会话，不改变保留规则）。"""
    sessions = ad_list(home, days)
    msgs = []
    tmp = Path(tempfile.mkdtemp(prefix="qj_ad_"))
    try:
        for s in sessions:
            tool = AD_NAMES.get(s.get("provider", ""), s.get("provider", "其他"))
            if not _ad_keep(s, only, projects, full_tools):
                continue
            if since is not None:
                t = parse_time(s.get("updated_at"))
                if t is not None and t <= since:
                    continue
            code, out, err = _ad_run(home, ["export", s["uri"], "--format", "json", "--output", str(tmp)])
            files = sorted((tmp / s.get("provider", "")).glob("*.json"), key=lambda p: p.stat().st_mtime)
            target = next((f for f in files if f.stem == str(s.get("id"))), files[-1] if files else None)
            if code != 0 or not target:
                ENGINE["notes"].append(f"导出失败，已跳过：{s['uri']}")
                continue
            try:
                d = json.loads(target.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue
            cwd = d.get("directory") or s.get("working_directory") or ""
            for m in d.get("messages") or []:
                role = m.get("role")
                if role not in ("user", "assistant"):
                    continue
                text = clean("\n".join(p.get("text", "") for p in m.get("parts") or [] if p.get("type") == "text"))
                if text:
                    ts = parse_time(m.get("time_created")) or parse_time(s.get("updated_at")) or dt.datetime.now(UTC)
                    msgs.append(Msg(tool, str(s.get("id")), cwd, ts, role, text, s["uri"]))
            try:
                target.unlink()
            except OSError:
                pass
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return msgs


def load_all(home: Path, only: set[str] | None = None, projects: set[str] | None = None,
             full_tools: set[str] | None = None, since: dt.datetime | None = None):
    """主引擎 agent-dump + 内置解析补齐它不支持的工具；没装 agent-dump 时全部用内置解析。"""
    if ad_bin():
        msgs = ad_load(home, only, projects=projects, full_tools=full_tools, since=since)
        rest = (only & BUILTIN_ONLY) if only else BUILTIN_ONLY
        if rest:
            msgs += load_all_builtin(home, rest)
        return msgs
    if ENGINE["name"] == "agent-dump":
        raise SystemExit("没有找到 agent-dump。请先运行：pip install agent-dump")
    return load_all_builtin(home, only)


def engine_label() -> str:
    b = ad_bin()
    if not b:
        return "内置解析（未安装 agent-dump）"
    import subprocess
    try:
        v = subprocess.run([b, "--version"], capture_output=True, text=True, timeout=20).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        v = "agent-dump"
    return f"{v}（WorkBuddy、CodeBuddy 用内置解析补充）"


# ------------------------------------------------ 飞书（官方通道，v2） ----
# 走飞书官方 CLI（lark-cli，开源）：只读两件事——列群、按日期拉消息；授权范围＝用户身份可见的群
# （平台安全模型：你/机器人不在的群读不到）。令牌由 lark-cli 存系统钥匙串，这里只起子进程，不落凭证。
# 没装 / 未授权 / 授权过期 → 记一条提示后跳过，不影响其他数据源（与 agent-dump 同一降级模式）。

def lark_bin() -> str | None:
    return shutil.which("lark-cli")


def lark_run(args: list[str], timeout: int = 120):
    import subprocess
    b = lark_bin()
    if not b:
        return None
    try:
        r = subprocess.run([b] + args, capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None
    try:
        return json.loads(r.stdout)
    except json.JSONDecodeError:
        return None


def feishu_auth() -> dict:
    """{ok, user, hint}；ok=False 时 hint 是下一步命令。"""
    d = lark_run(["auth", "status"]) or {}
    u = ((d.get("identities") or {}).get("user") or {})
    if u.get("available") and u.get("status") in ("ready", "needs_refresh"):
        return {"ok": True, "user": u.get("userName") or "已授权用户"}
    return {"ok": False, "user": None,
            "hint": "npm install -g @larksuite/cli && lark-cli auth login --domain im（扫码时只勾读消息权限）"}


def feishu_chats() -> list[dict]:
    d = lark_run(["im", "+chat-list", "--as", "user"]) or {}
    return [{"id": c.get("chat_id"), "name": c.get("name") or "(未命名群)"}
            for c in ((d.get("data") or {}).get("chats") or []) if c.get("chat_id")]


def feishu_msg_text(m: dict) -> str:
    """一条 lark-cli 消息 → 纯文本。卡片(interactive)的正文在顶层 content 字段里，逐层取 text/content/title。"""
    raw = m.get("content")
    t = m.get("msg_type", "")
    try:
        j = json.loads(raw) if isinstance(raw, str) and raw else (raw if isinstance(raw, dict) else {})
    except json.JSONDecodeError:
        j = None  # 卡片常以 <card …>…</card> 明文返回，本身就是可读文本
    if j is None:
        return str(raw or "").strip()
    if t == "text":
        return str(j.get("text", "")).strip()
    if t == "post":
        out, title = [], None
        if isinstance(j, dict):
            for lang in ([j] if isinstance(j.get("content"), list) else list(j.values())):
                if isinstance(lang, dict) and isinstance(lang.get("content"), list):
                    if not title:
                        t0 = lang.get("title")
                        title = (t0.get("zh_cn") or t0.get("title")) if isinstance(t0, dict) else t0
                    for para in lang["content"]:
                        if isinstance(para, list):
                            out += [e.get("text", "") for e in para if isinstance(e, dict) and e.get("tag") == "text"]
        return (f"{title} " if title else "") + " ".join(x for x in out if x).strip()
    if t == "interactive":
        seen, out = set(), []

        def walk(x):
            if isinstance(x, dict):
                for k, v in x.items():
                    if k in ("text", "content", "title") and isinstance(v, str) and v.strip() and v not in seen:
                        seen.add(v)
                        out.append(v.strip())
                    else:
                        walk(v)
            elif isinstance(x, list):
                for i in x:
                    walk(i)
        walk(j)
        return " ¦ ".join(out)
    return f"[{t}]" if t else ""


def load_feishu(since: dt.datetime | None, days: int = 14, only_chats: set[str] | None = None) -> list[Msg]:
    """拉用户身份可见各群 since 之后的消息（基线＝最近 days 天）。失败/未装 → [] 并记提示。"""
    if not lark_bin():
        return []
    a = feishu_auth()
    if not a["ok"]:
        ENGINE["notes"].append(f"飞书未接入：{a['hint']}")
        return []
    start = (since or dt.datetime.now(UTC) - dt.timedelta(days=days)).strftime("%Y-%m-%d")
    msgs: list[Msg] = []
    for c in feishu_chats():
        if only_chats and c["id"] not in only_chats:
            continue
        d = lark_run(["im", "+chat-messages-list", "--chat-id", c["id"], "--start", start, "--as", "user"]) or {}
        for m in (d.get("data") or {}).get("messages") or []:
            ts = parse_time(m.get("create_time"))
            if ts is None or (since is not None and ts <= since):
                continue
            text = feishu_msg_text(m)
            if not text:
                continue
            sender = (m.get("sender") or {}).get("name") or (m.get("sender") or {}).get("sender_type") or "?"
            msgs.append(Msg("飞书", c["name"], f"飞书/{c['name']}", ts, "user", text, None, who=str(sender)))
    return msgs


def connect_feishu(args):
    out = Path(args.out).expanduser() if args.out else default_out()
    out.mkdir(parents=True, exist_ok=True)
    if not lark_bin():
        print("未安装 lark-cli（飞书官方 CLI）。安装：npm install -g @larksuite/cli")
        print("装好后重新运行：python3 scripts/workbench.py connect feishu")
        return 1
    a = feishu_auth()
    if not a["ok"]:
        print("lark-cli 还没完成飞书授权，两步：")
        print("  1) lark-cli auth login --domain im   （扫码链接，只勾「读消息」类权限）")
        print("  2) 扫码确认后，重新运行 connect feishu")
        return 1
    chats = feishu_chats()
    scope_p = out / "scope.json"
    scope = json.loads(scope_p.read_text(encoding="utf-8")) if scope_p.exists() else {}
    scope["feishu"] = {"enabled": True, "chats": [], "connected_at": dt.datetime.now(UTC).isoformat()}
    scope_p.write_text(json.dumps(scope, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"✓ 飞书已接入：用户「{a['user']}」，可见 {len(chats)} 个群，下次 collect 自动拉取增量。")
    if chats:
        preview = "、".join(c["name"] for c in chats[:5])
        print(f"  群（前 5 个）：{preview}{'…' if len(chats) > 5 else ''}")
    print("  范围＝你的账号可见的群（平台安全模型：不在的群读不到）。配置：scope.json 的 feishu 节")
    print("  停用：feishu.enabled 改 false，或 lark-cli auth logout")
    return 0


def connect_cmd(args):
    if args.channel == "feishu":
        return connect_feishu(args)
    return 2


# ------------------------------------------------------------- 工作台 ----
def default_out() -> Path:
    return Path.home() / "清见工作台"


def load_state(out: Path) -> dict:
    p = out / "state.json"
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            pass
    return {"baseline_done": False, "cursor": None, "runs": []}


def save_state(out: Path, st: dict):
    (out / "state.json").write_text(json.dumps(st, ensure_ascii=False, indent=2), encoding="utf-8")


def project_name(p: str) -> str:
    if not p:
        return "（未归属项目）"
    return re.split(r"[\\/]", p.rstrip("\\/"))[-1] or p


def summarize(msgs) -> dict:
    by_tool = defaultdict(lambda: {"sessions": set(), "messages": 0, "first": None, "last": None, "projects": defaultdict(int)})
    for m in msgs:
        d = by_tool[m.tool]
        d["sessions"].add(m.session)
        d["messages"] += 1
        d["first"] = min(d["first"], m.ts) if d["first"] else m.ts
        d["last"] = max(d["last"], m.ts) if d["last"] else m.ts
        d["projects"][m.project] += 1
    out = {}
    for tool, d in by_tool.items():
        out[tool] = {
            "sessions": len(d["sessions"]), "messages": d["messages"],
            "first": d["first"].date().isoformat() if d["first"] else None,
            "last": d["last"].date().isoformat() if d["last"] else None,
            "projects": sorted(d["projects"].items(), key=lambda x: -x[1]),
        }
    return out


def summ_from_adlist(home: Path) -> dict | None:
    """快速统计：只用 agent-dump 列表元数据（条数、时间、工作目录），不导出会话内容。
    会话上千条时 pick 的统计才不会卡十几分钟；返回 None 表示不可用，调用方退回 summarize(load_all())。
    注意：这里的「N 条」是 agent-dump 的 message_count（全部消息），与慢路径的统计口径略有差异，仅用于选择页面展示。"""
    if not ad_bin():
        return None
    sessions = ad_list(home)
    if not sessions:
        return None

    def _ts(v):
        try:
            t = dt.datetime.fromisoformat(str(v).replace("Z", "+00:00"))
            return t.replace(tzinfo=dt.timezone.utc) if t.tzinfo is None else t
        except ValueError:
            return None

    by_tool = defaultdict(lambda: {"sessions": 0, "messages": 0, "first": None, "last": None,
                                   "projects": defaultdict(int)})
    for s in sessions:
        d = by_tool[AD_NAMES.get(s.get("provider", ""), s.get("provider", "其他"))]
        n = int(s.get("message_count") or 0)
        d["sessions"] += 1
        d["messages"] += n
        for k in ("created_at", "updated_at"):
            t = _ts(s.get(k))
            if t:
                d["first"] = min(d["first"], t) if d["first"] else t
                d["last"] = max(d["last"], t) if d["last"] else t
        d["projects"][s.get("working_directory") or ""] += n
    return {tool: {"sessions": d["sessions"], "messages": d["messages"],
                   "first": d["first"].date().isoformat() if d["first"] else None,
                   "last": d["last"].date().isoformat() if d["last"] else None,
                   "projects": sorted(d["projects"].items(), key=lambda x: -x[1])}
            for tool, d in by_tool.items()}


# ------------------------------------------------------------ 选择页面 ----
# -------------------------------------------------------- 技能白名单 ----
# 第 2 步用 find-skills 的方式（npx skills find）按场景找现成技能，但只允许装白名单来源的。
# 白名单 = 下面的默认值 + 技能目录下「技能白名单.txt」（每行一个 owner 或 owner/repo，# 开头为注释）。
DEFAULT_SKILL_SOURCES = ("anthropics", "vercel-labs")


def skill_whitelist() -> set:
    allow = set(DEFAULT_SKILL_SOURCES)
    f = Path(__file__).resolve().parent.parent / "技能白名单.txt"
    if f.exists():
        for line in f.read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                allow.add(line.lower())
    return allow


def skill_allowed(skill_id: str) -> bool:
    """skill_id 形如 owner/repo@skill；owner 或 owner/repo 在白名单里才允许。"""
    src = skill_id.split("@")[0].strip().lower()
    if not re.fullmatch(r"[a-z0-9_.-]+/[a-z0-9_.-]+", src):
        return False
    owner = src.split("/")[0]
    wl = skill_whitelist()
    return owner in wl or src in wl


PICK_CSS = """
:root{--bg:#eef3f3;--paper:#ffffff;--ink:#14262b;--ink2:#4a5d62;--line:#d3dfe0;--teal:#0f6b6b;--teal-soft:#e2f0ef;
--amber:#fff4d6;--amber-line:#e3c26a;--err:#b3261e;--err-soft:#fdecea}
*{box-sizing:border-box}
html{font-size:17px}
body{margin:0;background:var(--bg);color:var(--ink);font-family:"PingFang SC","Hiragino Sans GB","Microsoft YaHei",system-ui,sans-serif;line-height:1.6;accent-color:var(--teal)}
.wrap{max-width:780px;margin:0 auto;padding:36px 22px 150px}
header h1{font-size:30px;line-height:1.25;margin:0 0 8px;font-weight:700;letter-spacing:.02em}
header p{margin:0;color:var(--ink2);font-size:16px}
.plan{margin:26px 0 8px;background:var(--teal-soft);border-left:6px solid var(--teal);border-radius:4px 14px 14px 4px;padding:18px 22px}
.plan .k{font-size:15px;color:var(--teal);font-weight:600;margin-bottom:2px}
.plan h2{font-size:22px;margin:0 0 6px}
.plan p{margin:0 0 10px}
.plan dl{display:grid;grid-template-columns:5.5em 1fr;gap:4px 12px;margin:0 0 10px;font-size:16px}
.plan dt{color:var(--ink2)}.plan dd{margin:0}
.plan ul{list-style:none;padding:0;margin:0;font-size:16px}.plan li{margin:3px 0}
.plan .fb{font-size:15px;color:var(--ink2);margin-top:8px}
fieldset.step{border:0;margin:34px 0 0;padding:0 0 0 64px;position:relative;min-width:0}
fieldset.step>legend{float:left;width:100%;padding:0;font-size:24px;line-height:44px;font-weight:700;margin:0 0 12px}
fieldset.step>legend+*{clear:both}
.num{position:absolute;left:0;top:0;width:44px;height:44px;border-radius:50%;background:var(--ink);color:#fff;
display:flex;align-items:center;justify-content:center;font-size:20px;font-weight:700}
.box{background:var(--paper);border:1px solid var(--line);border-radius:12px;padding:16px 20px;margin:0 0 12px}
.box.v2{background:transparent;border-style:dashed;color:var(--ink2)}
.row{display:flex;align-items:flex-start;gap:12px;margin:8px 0;cursor:pointer}
.row>input{margin-top:5px}
input[type=checkbox],input[type=radio]{width:20px;height:20px;flex:none}
.big{font-size:18px;font-weight:600}
.hint{display:block;color:var(--ink2);font-size:15px;margin-top:2px;font-weight:400}
.pill{display:inline-block;font-size:14px;font-weight:600;color:var(--teal);background:var(--teal-soft);border-radius:999px;padding:0 10px;margin-left:8px;vertical-align:2px}
.pill.gray{color:var(--ink2);background:#e6ebec}
.sub{margin:10px 0 0 32px;padding:12px 16px;border-radius:10px;background:#f6f9f9}
.sub h3{font-size:16px;margin:0 0 6px}
.summary{margin:8px 0 0 32px;color:var(--ink2);font-size:15px}
.tools{margin:6px 0 0 32px}
.tool{border:1px solid var(--line);border-radius:10px;margin:8px 0;background:#fbfdfd}
.tool .head{display:flex;align-items:center;gap:12px;padding:10px 14px;flex-wrap:wrap}
.tool .head .meta{color:var(--ink2);font-size:15px}
.tool details{border-top:1px solid var(--line)}
.tool summary{cursor:pointer;padding:8px 14px;color:var(--teal);font-size:15px;font-weight:600}
.tool summary .cnt{color:var(--ink2);font-weight:400;margin-left:6px}
.filter{width:calc(100% - 28px);margin:4px 14px 8px;font:inherit;font-size:15px;padding:7px 10px;border:1px solid var(--line);border-radius:8px}
.plist{max-height:300px;overflow:auto;padding:0 14px 10px}
.proj{display:grid;grid-template-columns:20px 1fr auto;gap:2px 12px;align-items:start;padding:6px 0;border-bottom:1px dashed #e3eaeb;cursor:pointer}
.proj:last-child{border-bottom:0}
.proj .pn{font-size:16px}.proj .pc{color:var(--ink2);font-size:14px;white-space:nowrap}
.proj .pp{grid-column:2/4;color:var(--ink2);font-size:13px;overflow-wrap:anywhere}
.field{display:block;margin:12px 0}
.field>span{display:block;font-weight:600;margin-bottom:4px}
.field small{font-weight:400;color:var(--ink2);font-size:15px;margin-left:6px}
input[type=text],select,textarea{font:inherit;font-size:16px;color:var(--ink);background:#fff;border:1px solid #b9c9cb;border-radius:8px;padding:7px 10px}
input[type=text],textarea{width:100%}
input[type=text].short{width:16em;max-width:100%}
select{padding:6px 8px}
.inline{display:inline-flex;gap:8px;align-items:center;flex-wrap:wrap}
:focus-visible{outline:3px solid #f0b429;outline-offset:2px}
.consent{background:var(--amber);border-color:var(--amber-line)}
.consent ul{margin:0 0 10px;padding-left:1.2em}.consent li{margin:4px 0}
.err{display:none;margin:10px 0 0;padding:10px 14px;border-radius:8px;background:var(--err-soft);color:var(--err);font-weight:600}
.err.on{display:block}
.bar{position:fixed;left:0;right:0;bottom:0;background:rgba(255,255,255,.97);border-top:2px solid var(--ink);box-shadow:0 -6px 20px rgba(20,38,43,.08)}
.bar .in{max-width:780px;margin:0 auto;padding:12px 22px;display:flex;gap:18px;align-items:center}
.bar .say{flex:1;font-size:16px;line-height:1.5}
.bar .say b{color:var(--teal)}
.bar .why{display:block;font-size:14px;color:var(--ink2)}
.btn{font:inherit;font-size:18px;font-weight:700;background:var(--teal);color:#fff;border:0;border-radius:10px;padding:12px 26px;cursor:pointer;white-space:nowrap}
.btn:disabled{background:#9fb3b5;cursor:not-allowed}
@media (max-width:640px){html{font-size:16px}fieldset.step{padding-left:0}.num{position:static;display:inline-flex;margin-bottom:8px}
.bar .in{flex-direction:column;align-items:stretch}.btn{width:100%}.sub,.tools,.summary{margin-left:0}}
@media (prefers-reduced-motion:reduce){*{scroll-behavior:auto!important}}
"""

PICK_HTML = """<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="icon" href="data:,"><title>清见工作台 · 选择数据源和触发器</title><style>__CSS__</style>
<div class="wrap">
<header><h1>搭建你的个人工作台</h1>
<p>这个页面只在你自己的电脑上运行，不联网。没勾选的内容，一条都不会被读取。</p></header>
__PLAN__
<form id="f" method="post" action="/submit?t=__TOKEN__" novalidate>

<fieldset class="step" id="s1"><div class="num" aria-hidden="true">1</div><legend>选择数据源</legend>
<div class="box">
<label class="row"><input type="checkbox" name="src" value="ai_sessions" __AI_CHECKED__>
<span><span class="big">本地 AI 会话</span><span class="pill">基础盘，一定有数据</span>
<span class="hint">把你在各个 AI 工具里的会话放进同一个上下文。</span></span></label>
<div class="sub" id="aiopts">
<label class="row"><input type="radio" name="mode" value="all" checked><span>全部工具、全部项目</span></label>
<div class="summary" id="allsum">__SUMMARY__</div>
<label class="row"><input type="radio" name="mode" value="pick"><span>只用我勾选的工具或项目</span></label>
<div class="tools" id="tools" hidden>__SOURCES__</div>
<h3 style="margin-top:14px">时间范围</h3>
<label class="row"><input type="radio" name="range" value="auto" checked><span>自动<span class="hint">数据多就只取最近 14 天，少就全部</span></span></label>
<label class="row"><input type="radio" name="range" value="14"><span>最近 14 天</span></label>
<label class="row"><input type="radio" name="range" value="all"><span>全部历史</span></label>
<label class="row"><input type="checkbox" name="assistant" value="1"><span>同时包含 AI 的回复<span class="hint">默认只取你自己说的话，更省额度、更安全</span></span></label>
</div></div>
<div class="box">
<label class="row"><input type="checkbox" name="src" value="folder" __FOLDER_CHECKED__>
<span><span class="big">本地文件夹</span><span class="hint">每行一个文件夹路径，读取其中的 .md、.txt、.csv、.json 文件（单个文件 300KB 以内）。</span></span></label>
<textarea name="folders" rows="2" placeholder="例如：D:\\工作\\周报素材" aria-label="文件夹路径，每行一个">__FOLDERS__</textarea></div>
<div class="box">
<label class="row"><input type="checkbox" name="src" value="inbox" __INBOX_CHECKED__>
<span><span class="big">收集箱</span><span class="hint">在工作台里建一个「收集箱」文件夹。拿不到的数据（比如微信里的要点），复制成文件丢进去，后面全自动。</span></span></label></div>
<div class="box v2">
<label class="row"><input type="checkbox" disabled>
<span><span class="big">企业微信、飞书、钉钉</span><span class="pill gray">v2 · 暂不可选</span>
<span class="hint">有官方接口，但通常需要企业管理员开通。现在先用收集箱，开通后再接。个人微信没有合规接口，不接入。</span></span></label></div>
<div class="err" id="e1" role="alert"></div>
</fieldset>

<fieldset class="step" id="s2"><div class="num" aria-hidden="true">2</div><legend>选择触发器</legend>
<div class="box">
<label class="row"><input type="radio" name="trigger" value="daily" __T_DAILY__>
<span class="inline">每天定时 <select name="daily_time" aria-label="每天几点">__DAILY_OPTS__</select></span></label>
<label class="row"><input type="radio" name="trigger" value="weekly" __T_WEEKLY__>
<span class="inline">每周定时 <select name="weekday" aria-label="每周哪天">__WEEKDAYS__</select> <select name="weekly_time" aria-label="几点">__WEEKLY_OPTS__</select></span></label>
<label class="row"><input type="radio" name="trigger" value="manual" __T_MANUAL__>
<span class="inline">手动：对 AI 说一句 <input type="text" class="short" name="phrase" value="__PHRASE__" aria-label="口令"></span></label>
<p class="hint">定时任务由你正在用的 AI 工具执行，需要电脑开着；电脑经常关机的，选「手动」更稳。</p></div>
</fieldset>

<fieldset class="step" id="s3"><div class="num" aria-hidden="true">3</div><legend>确认输出物</legend>
<div class="box">
<label class="field"><span>它是什么</span><input type="text" name="out_type" value="__OUT_TYPE__"></label>
<label class="field"><span>包含哪几块<small>每行一块，会变成固定模板的小标题</small></span>
<textarea name="out_items" rows="__OUT_ROWS__">__OUT_ITEMS__</textarea></label>
<label class="field"><span>给谁看</span><input type="text" name="out_aud" value="__OUT_AUD__"></label>
<div class="field"><span>什么样子</span>
<label class="row"><input type="radio" name="out_format" value="page" __FMT_PAGE__><span>工作台主页<span class="hint">推荐：每天打开同一个网页；AI 按你的内容设计版式，每次运行后自动更新</span></span></label>
<label class="row"><input type="radio" name="out_format" value="md" __FMT_MD__><span>文字版（Markdown）<span class="hint">最稳，任何工具都能打开</span></span></label>
<label class="row"><input type="radio" name="out_format" value="html" __FMT_HTML__><span>网页简报<span class="hint">套用清见的网页模板，排版好看，可以直接用浏览器打开或转发</span></span></label></div>
<div class="field"><span>怎么交付</span>
<label class="row"><input type="checkbox" checked disabled><span>保存到工作台的「输出」文件夹<span class="hint">每次一份，按日期命名；这一项固定开启</span></span></label>
<label class="row"><input type="checkbox" name="deliver" value="wecom"><span>同时推送到企业微信群<span class="hint">需要群机器人地址，放在环境变量 WECOM_WEBHOOK 里，不写进任何文件</span></span></label></div>
__SKILLS__
<p class="hint">每份结果最后都会附一行「反馈」：你回一句「好」或「以后不用写 xx」，下次就会照着改。</p></div>
</fieldset>

<fieldset class="step" id="s4"><div class="num" aria-hidden="true">4</div><legend>确认授权</legend>
<div class="box consent">
<ul><li>收集时会自动遮挡：密钥、令牌、密码、身份证号、银行卡号、手机号、邮箱、电脑用户名。</li>
<li>整理好的「素材包」会交给 __MODEL__ 来生成结果。<b>只有这一步会离开你的电脑。</b></li>
<li>素材包生成后，你可以先打开看一遍，再决定要不要继续。</li></ul>
<label class="row"><input type="checkbox" name="consent" value="1" id="ok"><span class="big">我已了解，同意按以上范围搭建</span></label></div>
</fieldset>

<div class="bar"><div class="in">
<div class="say" id="say" aria-live="polite"></div>
<button class="btn" id="go" type="submit" disabled>确认，开始搭建</button></div></div>
</form></div>
<script>
(function(){
var f=document.getElementById('f'),$=function(s,r){return (r||f).querySelector(s)},$$=function(s,r){return Array.prototype.slice.call((r||f).querySelectorAll(s))};
function val(n){var e=$('[name='+n+']:checked');return e?e.value:''}
function aiOn(){return $('input[name=src][value=ai_sessions]').checked}
function sync(){
  var on=aiOn(),pick=val('mode')==='pick';
  $$('#aiopts input').forEach(function(e){if(!e.classList.contains('sel'))e.disabled=!on});
  $('#aiopts').style.opacity=on?1:.45;
  $('#tools').hidden=!(on&&pick);$('#allsum').hidden=!(on&&!pick);
  $$('.sel').forEach(function(e){e.disabled=!(on&&pick)});
  say();
}
function toolState(t){
  var ps=$$('.psel[data-t="'+t+'"]'),n=ps.filter(function(p){return p.checked}).length,tc=$('.tsel[data-t="'+t+'"]');
  tc.checked=ps.length>0&&n===ps.length;tc.indeterminate=n>0&&n<ps.length;
  var c=$('[data-cnt="'+t+'"]');if(c)c.textContent=tc.checked?'已全选':(n?'已选 '+n+' / '+ps.length:'未选');
}
f.addEventListener('change',function(e){
  var t=e.target;
  if(t.classList.contains('tsel')){$$('.psel[data-t="'+t.dataset.t+'"]').forEach(function(p){p.checked=t.checked});toolState(t.dataset.t)}
  else if(t.classList.contains('psel')){toolState(t.dataset.t)}
  if(t.id==='ok')$('#go').disabled=!t.checked;
  if(t.name==='src'||t.name==='mode')sync();else say();
  $$('.err').forEach(function(x){x.classList.remove('on')});
});
f.addEventListener('input',function(e){if(e.target.classList.contains('filter')){var q=e.target.value.trim().toLowerCase();
  $$('.proj',e.target.parentNode).forEach(function(l){l.hidden=q&&l.dataset.name.indexOf(q)<0})}else say()});
function srcText(){
  var s=[];if(aiOn()){var pick=val('mode')==='pick';
    if(!pick)s.push('全部 AI 会话');else{var n=$$('.tsel:checked').length+$$('.psel:checked').filter(function(p){return !$('.tsel[data-t="'+p.dataset.t+'"]').checked}).length;s.push(n?'勾选的 AI 会话':'AI 会话（还没勾选）')}}
  if($('input[name=src][value=folder]').checked)s.push('本地文件夹');
  if($('input[name=src][value=inbox]').checked)s.push('收集箱');
  return s.join('、');
}
function trigText(){var t=val('trigger');
  if(t==='daily')return '每天 '+$('[name=daily_time]').value;
  if(t==='weekly')return '每'+$('[name=weekday]').value+' '+$('[name=weekly_time]').value;
  return '说「'+($('[name=phrase]').value||'运行我的工作台')+'」时';}
function say(){
  var src=srcText(),items=$('[name=out_items]').value.split('\\n').filter(function(x){return x.trim()}).length;
  var fmt={html:'网页简报',page:'工作台主页'}[val('out_format')]||'文字版纪要';
  $('#say').innerHTML=src?('读取<b>'+esc(src)+'</b>，<b>'+esc(trigText())+'</b>生成一份<b>'+items+' 块的'+fmt+'</b>。')
    :'还没有选择数据源。';
  if(!$('#ok').checked)$('#say').innerHTML+='<span class="why">勾选第 4 步的「我已了解」后，就可以确认。</span>';
}
function esc(s){return String(s).replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]})}
function fail(id,msg,sec){var e=document.getElementById(id);e.textContent=msg;e.classList.add('on');
  document.getElementById(sec).scrollIntoView({behavior:'smooth',block:'start'});return false}
f.addEventListener('submit',function(e){
  if(!$('input[name=src]:checked')){e.preventDefault();return fail('e1','请至少选择一个数据源。','s1')}
  if(aiOn()&&val('mode')==='pick'&&!$('.sel:checked')){e.preventDefault();return fail('e1','你选了「只用我勾选的」，但还没有勾选任何工具或项目。展开下面的工具勾选，或改回「全部」。','s1')}
  if(!$('#ok').checked){e.preventDefault();return false}
  $('#go').disabled=true;$('#go').textContent='正在保存…';
});
$$('.tsel').forEach(function(t){toolState(t.dataset.t)});sync();
})();
</script></html>"""

WEEKDAYS = ["周一", "周二", "周三", "周四", "周五", "周六", "周日"]


def _time_opts(selected: str) -> str:
    times = [f"{h:02d}:{m:02d}" for h in range(6, 24) for m in (0, 30)]
    if selected and selected not in times:
        times.append(selected)
        times.sort()
    return "".join(f'<option{" selected" if t == selected else ""}>{t}</option>' for t in times)


def _plan_card(plan: dict) -> str:
    if not plan:
        return ""
    e = html.escape
    out = plan.get("output") or {}
    if isinstance(out, dict):
        rows = "".join(f"<dt>{e(str(k))}</dt><dd>{e(v if isinstance(v, str) else '、'.join(map(str, v)))}</dd>"
                       for k, v in out.items())
    else:
        rows = f"<dt>输出物</dt><dd>{e(str(out))}</dd>"
    review = plan.get("review") or {}
    rv = "".join(f"<li>{e(str(k))}：{e(str(v))}</li>" for k, v in review.items())
    fb = plan.get("fallback")
    return (f'<section class="plan" aria-label="AI 的落地分析"><div class="k">AI 的落地分析，下面的选项已按它预先填好</div>'
            f'<h2>{e(plan.get("name", "我的工作台"))}</h2><p>{e(plan.get("scenario", ""))}</p>'
            f'<dl>{rows}</dl><ul>{rv}</ul>' + (f'<div class="fb">降级方案：{e(str(fb))}</div>' if fb else "") + "</section>")


def _tools_block(summ: dict, red) -> tuple:
    """返回 (工具列表 HTML, 「全部」模式下的一行汇总)。项目不截断；超过 8 个时提供搜索框。"""
    e = html.escape
    blocks, parts = [], []
    total_s = total_p = 0
    for i, (tool, d) in enumerate(sorted(summ.items(), key=lambda kv: -kv[1]["sessions"])):
        projs = d["projects"]
        total_s += d["sessions"]
        total_p += len(projs)
        parts.append(f"{e(tool)} {d['sessions']} 个会话")
        items = "".join(
            f'<label class="proj" data-name="{e(project_name(p).lower())}"><input class="sel psel" type="checkbox" name="proj" '
            f'value="{e(tool)}::{e(p)}" data-t="{i}"><span class="pn">{e(project_name(p))}</span>'
            f'<span class="pc">{n} 条</span><span class="pp">{e(red.path(p) or "未归属项目")}</span></label>'
            for p, n in projs)
        search = f'<input type="search" class="filter" placeholder="搜索项目名" aria-label="搜索 {e(tool)} 的项目">' if len(projs) > 8 else ""
        blocks.append(
            f'<div class="tool"><div class="head"><label class="row" style="margin:0"><input class="sel tsel" type="checkbox" '
            f'name="tool" value="{e(tool)}" data-t="{i}"><span class="big">{e(tool)}</span></label>'
            f'<span class="meta">{d["sessions"]} 个会话，{len(projs)} 个项目，{d["first"]} 至 {d["last"]}</span></div>'
            f'<details><summary>按项目选<span class="cnt" data-cnt="{i}">未选</span></summary>{search}'
            f'<div class="plist">{items}</div></details></div>')
    if not blocks:
        return ('<p class="hint">这台电脑上没有找到支持的 AI 工具会话。可以只用文件夹和收集箱；或之后运行 discover / import。</p>',
                "这台电脑上没有找到 AI 工具会话。")
    head = f"共 {len(blocks)} 个工具、{total_s} 个会话、{total_p} 个项目：" + "；".join(parts) + "。"
    return "".join(blocks), head


def _skills_block(plan: dict) -> str:
    """第③部分里的「用到的技能」：只展示 AI 在第 2 步找到的技能；不在白名单里的不可勾选。"""
    sk = plan.get("skills_suggested") or []
    if not sk:
        return ""
    e = html.escape
    rows = []
    for s in sk:
        sid = str(s.get("id", "")).strip()
        if not sid:
            continue
        ok = skill_allowed(sid)
        src = sid.split("@")[0]
        extra = f'{e(src)}' + (f'，安装量 {e(str(s["installs"]))}' if s.get("installs") else "")
        rows.append(
            f'<label class="row"><input type="checkbox" name="skill" value="{e(sid)}" {"checked" if ok and s.get("recommended", True) else ""} '
            f'{"" if ok else "disabled"}><span>{e(s.get("name") or sid)}<span class="hint">{e(s.get("why") or s.get("desc") or "")}'
            f'</span><span class="hint">来源：{extra}' + ("" if ok else "（不在清见白名单里，需要讲师审核后才能用）") + '</span></span></label>')
    if not rows:
        return ""
    return ('<div class="field"><span>用到的技能<small>AI 按你的场景找到的现成技能，勾选的会装进你的工作台</small></span>'
            + "".join(rows) + "</div>")


def _success_page(form: dict) -> str:
    e = html.escape
    g = lambda k, d="": form.get(k, [d])[0]
    src = {"ai_sessions": "本地 AI 会话", "folder": "本地文件夹", "inbox": "收集箱"}
    srcs = "、".join(src.get(s, s) for s in form.get("src", []))
    if "ai_sessions" in form.get("src", []):
        n = len(form.get("tool", [])) + len(form.get("proj", []))
        srcs += "（全部工具）" if g("mode", "all") != "pick" else f"（勾选了 {n} 项）"
    t = g("trigger", "daily")
    trig = {"daily": f"每天 {g('daily_time')}", "weekly": f"每{g('weekday')} {g('weekly_time')}"}.get(t, f"手动：说「{g('phrase')}」")
    items = "、".join(x.strip() for x in g("out_items").splitlines() if x.strip())
    fmt = {"html": "网页简报", "page": "工作台主页"}.get(g("out_format"), "文字版")
    skills = "、".join(form.get("skill", [])) or "无"
    return ("<!doctype html><html lang='zh-CN'><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
            "<title>已保存</title><style>body{font-family:'PingFang SC','Microsoft YaHei',system-ui,sans-serif;background:#eef3f3;color:#14262b;"
            "font-size:18px;line-height:1.7;margin:0}main{max-width:640px;margin:60px auto;padding:0 22px}h1{font-size:28px;margin:0 0 6px}"
            "dl{display:grid;grid-template-columns:5em 1fr;gap:6px 14px;background:#fff;border:1px solid #d3dfe0;border-radius:12px;padding:18px 22px}"
            "dt{color:#4a5d62}dd{margin:0}p{color:#4a5d62}</style><main>"
            "<h1>✓ 已保存</h1><p>可以关闭这个页面，回到 AI 工具继续。</p>"
            f"<dl><dt>数据源</dt><dd>{e(srcs)}</dd><dt>触发器</dt><dd>{e(trig)}</dd>"
            f"<dt>输出物</dt><dd>{e(g('out_type'))}（{e(fmt)}）：{e(items)}</dd><dt>给谁看</dt><dd>{e(g('out_aud'))}</dd>"
            f"<dt>技能</dt><dd>{e(skills)}</dd></dl>"
            "<p>想改？回到 AI 工具说「重新选择」，会重新打开这个页面。这个页面的服务已经关闭，刷新会打不开，这是正常的。</p></main></html>")


def _out_field(plan: dict, key: str, default: str) -> str:
    o = plan.get("output")
    return str(o.get(key) or default) if isinstance(o, dict) else default


def _out_items(plan: dict) -> list:
    o = plan.get("output")
    items = o.get("包含") if isinstance(o, dict) else None
    if isinstance(items, str):
        items = re.split(r"[、，,;；\n]+", items)
    return [x.strip() for x in (items or ["今天做了什么（按项目）", "反复出现的事", "待收尾"]) if x.strip()]


def pick(args):
    home = Path(args.home).expanduser() if args.home else Path.home()
    out = Path(args.out).expanduser() if args.out else default_out()
    out.mkdir(parents=True, exist_ok=True)
    plan_p = Path(args.plan) if args.plan else out / "方案.json"
    plan = {}
    if plan_p.exists():
        try:
            plan = json.loads(plan_p.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            print(f"方案文件格式不对，已忽略：{plan_p}")
    print("正在统计本地 AI 会话（只计数，不输出内容）……")
    summ = summ_from_adlist(home)  # 快路径：只用 agent-dump 列表元数据
    if summ is None:               # 没装 agent-dump 或列表失败 → 原来的慢路径
        summ = summarize(load_all(home))
    else:                          # 补上 agent-dump 不支持、靠内置解析的工具（WorkBuddy 等）
        summ.update(summarize(load_all_builtin(home, BUILTIN_ONLY)))
    red = Redactor(home)
    tools_html, all_summary = _tools_block(summ, red)
    sug = set(plan.get("suggested_sources") or ["ai_sessions"])
    trig = plan.get("suggested_trigger") or {}
    ttype = trig.get("type", "daily")
    wd = trig.get("weekday", "周五")
    ck = lambda b: "checked" if b else ""
    out_items = _out_items(plan)
    fmt = str((plan.get("output") or {}).get("形式", "") if isinstance(plan.get("output"), dict) else "")
    fmt_html = fmt in ("html", "网页", "网页简报")
    fmt_page = fmt in ("page", "主页", "工作台主页")
    t_time = trig.get("time", "18:00")
    page = (PICK_HTML.replace("__CSS__", PICK_CSS).replace("__PLAN__", _plan_card(plan))
            .replace("__SOURCES__", tools_html).replace("__SUMMARY__", html.escape(all_summary))
            .replace("__TOKEN__", "{TOKEN}")
            .replace("__AI_CHECKED__", ck("ai_sessions" in sug and summ)).replace("__FOLDER_CHECKED__", ck("folder" in sug))
            .replace("__INBOX_CHECKED__", ck("inbox" in sug))
            .replace("__FOLDERS__", html.escape("\n".join(plan.get("folders") or [])))
            .replace("__T_DAILY__", ck(ttype == "daily")).replace("__T_WEEKLY__", ck(ttype == "weekly"))
            .replace("__T_MANUAL__", ck(ttype == "manual"))
            .replace("__DAILY_OPTS__", _time_opts(t_time)).replace("__WEEKLY_OPTS__", _time_opts(t_time))
            .replace("__PHRASE__", html.escape(trig.get("phrase", "运行我的工作台")))
            .replace("__WEEKDAYS__", "".join(f'<option{" selected" if w == wd else ""}>{w}</option>' for w in WEEKDAYS))
            .replace("__MODEL__", html.escape(args.model))
            .replace("__OUT_TYPE__", html.escape(_out_field(plan, "类型", "每日工作纪要")))
            .replace("__OUT_ITEMS__", html.escape("\n".join(out_items)))
            .replace("__OUT_ROWS__", str(max(3, len(out_items) + 1)))
            .replace("__OUT_AUD__", html.escape(_out_field(plan, "给谁看", "自己")))
            .replace("__FMT_MD__", ck(not fmt_html and not fmt_page)).replace("__FMT_HTML__", ck(fmt_html))
            .replace("__FMT_PAGE__", ck(fmt_page))
            .replace("__SKILLS__", _skills_block(plan)))
    left = re.findall(r"__[A-Z_]+__", page)
    if left:
        raise SystemExit(f"页面模板有未替换的占位符：{left}")
    token = secrets.token_urlsafe(16)
    page = page.replace("{TOKEN}", token)
    done = threading.Event()
    result = {}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, body: str, code=200):
            b = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_GET(self):
            if parse_qs(urlparse(self.path).query).get("t", [""])[0] != token:
                return self._send("无效的链接", 403)
            self._send(page)

        def do_POST(self):
            if parse_qs(urlparse(self.path).query).get("t", [""])[0] != token:
                return self._send("无效的链接", 403)
            n = int(self.headers.get("Content-Length") or 0)
            form = parse_qs(self.rfile.read(n).decode("utf-8"), keep_blank_values=True)
            if form.get("consent") != ["1"]:
                return self._send("没有勾选同意，未保存任何选择。可以关闭页面。")
            if not form.get("src"):
                return self._send("没有选择数据源，未保存。请返回重新选择。")
            result.update(form)
            self._send(_success_page(form))
            done.set()

    srv = HTTPServer(("127.0.0.1", args.port), H)
    url = f"http://127.0.0.1:{srv.server_address[1]}/?t={token}"
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print(f"请在浏览器打开（只在本机有效）：\n  {url}")
    if not args.no_browser:
        webbrowser.open(url)
    ok = done.wait(timeout=args.timeout)
    srv.shutdown()
    if not ok:
        print("等待超时，未保存选择。")
        return 1
    g = lambda k, d="": result.get(k, [d])[0]
    srcs = result.get("src", [])
    t = g("trigger", "daily")
    trigger = {"type": t}
    if t == "daily":
        trigger["time"] = g("daily_time", "18:00")
    elif t == "weekly":
        trigger.update(weekday=g("weekday", "周五"), time=g("weekly_time", "18:00"))
    else:
        trigger["phrase"] = g("phrase", "运行我的工作台").strip() or "运行我的工作台"
    scope = {
        "use_sessions": "ai_sessions" in srcs,
        "mode": g("mode", "all"),
        "tools": result.get("tool", []),
        "projects": result.get("proj", []),
        "folders": [x.strip() for x in g("folders").splitlines() if x.strip()] if "folder" in srcs else [],
        "inbox": "inbox" in srcs,
        "range": g("range", "auto"),
        "assistant": result.get("assistant") == ["1"],
        "trigger": trigger,
        "output": {
            "type": g("out_type", "每日工作纪要").strip() or "每日工作纪要",
            "items": [x.strip() for x in g("out_items").splitlines() if x.strip()] or ["今天做了什么", "待收尾"],
            "audience": g("out_aud", "自己").strip() or "自己",
            "delivery": ["save"] + (["wecom"] if "wecom" in result.get("deliver", []) else []),
            "format": g("out_format", "md") if g("out_format", "md") in ("html", "page") else "md",
        },
        "skills": [x for x in result.get("skill", []) if skill_allowed(x)],
        "plan": plan.get("name", ""),
        "consent": {"at": dt.datetime.now(UTC).isoformat(), "model": args.model},
        "home": str(home.resolve()),
    }
    (out / "scope.json").write_text(json.dumps(scope, ensure_ascii=False, indent=2), encoding="utf-8")
    if scope["inbox"]:
        (out / "收集箱").mkdir(exist_ok=True)
    print(f"已保存：{out / 'scope.json'}")
    print("数据源：" + "、".join({"ai_sessions": "本地 AI 会话", "folder": "本地文件夹", "inbox": "收集箱"}[s] for s in srcs))
    print("触发器：" + trigger_text(trigger))
    print("输出物：" + scope["output"]["type"] + "（" + "、".join(scope["output"]["items"]) + "）"
          + {"html": "，网页简报", "page": "，工作台主页"}.get(scope["output"]["format"], "，文字版"))
    if scope["skills"]:
        print("技能：" + "、".join(scope["skills"]) + "（搭建时安装）")
    return 0


def trigger_text(t: dict) -> str:
    if t.get("type") == "daily":
        return f"每天 {t.get('time', '18:00')}"
    if t.get("type") == "weekly":
        return f"每{t.get('weekday', '周五')} {t.get('time', '18:00')}"
    return f"手动：说「{t.get('phrase', '运行我的工作台')}」"


TEXT_EXT = (".md", ".txt", ".csv", ".json", ".markdown")


def load_folders(folders, tool: str):
    msgs = []
    for fd in folders:
        root = Path(fd).expanduser()
        if not root.is_dir():
            print(f"  跳过不存在的文件夹：{fd}")
            continue
        for f in sorted(root.rglob("*")):
            if not f.is_file() or f.suffix.lower() not in TEXT_EXT or any(p.startswith(".") for p in f.relative_to(root).parts):
                continue
            try:
                if f.stat().st_size > 300_000:
                    continue
                text = f.read_text(encoding="utf-8", errors="replace").strip()
            except OSError:
                continue
            if text:
                msgs.append(Msg(tool, str(f.relative_to(root)), str(root), fmtime(f), "user", text[:20000], str(f)))
    return msgs


def in_scope(m: Msg, scope: dict) -> bool:
    if scope.get("mode") != "pick":
        return True
    if m.tool in scope.get("tools", []):
        return True
    return f"{m.tool}::{m.project}" in scope.get("projects", [])


def load_prefs(out: Path) -> list:
    p = out / "偏好.md"
    if not p.exists():
        return []
    return [l for l in p.read_text(encoding="utf-8").splitlines() if l.startswith("- ")][-20:]


def write_pack(msgs, out: Path, red: Redactor, title: str, note: str, include_assistant: bool, budget: int) -> Path:
    sessions = defaultdict(list)
    for m in msgs:
        if m.role == "assistant" and not include_assistant:
            continue
        m.text = red(m.text.replace("\r", ""))  # 每条只脱敏一次
        sessions[(m.tool, m.session)].append(m)
    by_proj = defaultdict(list)
    for (tool, sid), ms in sessions.items():
        ms.sort(key=lambda x: x.ts)
        by_proj[ms[0].project].append((tool, sid, ms))
    # 预算控制：消息太多时每段会话少取几条、每条截短
    per_msg, per_sess = 600, 15
    total = sum(min(len(m.text), per_msg) for v in by_proj.values() for _, _, ms in v for m in ms[:per_sess])
    while total > budget and per_msg > 120:
        per_msg, per_sess = int(per_msg * 0.7), max(4, int(per_sess * 0.8))
        total = sum(min(len(m.text), per_msg) for v in by_proj.values() for _, _, ms in v for m in ms[:per_sess])
    lines = [f"# {title}", "", f"> {note}", "> 本素材包已在本地脱敏：" + red.report_placeholder, ""]
    prefs = load_prefs(out)
    if prefs:
        lines += ["## 我的偏好（来自以往反馈，生成结果时必须遵守）", ""] + prefs + [""]
    idx = ["", "## 项目索引", "", "| 项目 | 路径 | 工具 | 会话数 | 最近一次 |", "|---|---|---|---|---|"]
    for proj, items in sorted(by_proj.items(), key=lambda kv: -max(m.ts for _, _, ms in kv[1] for m in ms).timestamp()):
        last = max(m.ts for _, _, ms in items for m in ms)
        tools = "、".join(sorted({t for t, _, _ in items}))
        idx.append(f"| {project_name(proj)} | {red.path(proj) or '—'} | {tools} | {len(items)} | {last.astimezone().date()} |")
        lines += [f"## 项目：{project_name(proj)}", f"路径：{red.path(proj) or '—'}", ""]
        for tool, sid, ms in sorted(items, key=lambda x: x[2][0].ts):
            first = ms[0]
            head = first.session if tool in FILE_TOOLS else first.text.replace("\n", " ")[:40]
            lines.append(f"### {first.ts.astimezone().strftime('%Y-%m-%d %H:%M')} · {tool} · {head}")
            for m in ms[:per_sess]:
                t = m.text
                t = t if len(t) <= per_msg else t[:per_msg] + "……（已截断）"
                who = m.who or ("文件" if tool in FILE_TOOLS else "我" if m.role == "user" else "AI")
                lines.append(f"- **{who}**：" + t.replace("\n", "\n  "))
            if len(ms) > per_sess:
                lines.append(f"- ……本段会话另有 {len(ms) - per_sess} 条未列出")
            lines.append("")
    body = "\n".join(lines + idx).replace(red.report_placeholder, red.report())
    out.mkdir(parents=True, exist_ok=True)
    kind = "基线" if "基线" in title else "导入" if "导入" in title else "增量"
    p = out / "素材包" / f"{dt.date.today().isoformat()}_{kind}.md"
    p.parent.mkdir(exist_ok=True)
    if p.exists():
        p = p.with_name(p.stem + dt.datetime.now().strftime("_%H%M%S") + ".md")
    p.write_text(body + "\n", encoding="utf-8")
    return p


FILE_TOOLS = ("本地文件夹", "收集箱")
Redactor.report_placeholder = "\u0000REDACT_REPORT\u0000"


def collect(args):
    out = Path(args.out).expanduser() if args.out else default_out()
    out.mkdir(parents=True, exist_ok=True)
    scope_p = out / "scope.json"
    if scope_p.exists():
        scope = json.loads(scope_p.read_text(encoding="utf-8"))
    elif args.yes:
        scope = {"mode": "all", "range": "auto", "assistant": False,
                 "consent": {"at": dt.datetime.now(UTC).isoformat(), "model": "对话中已确认"}}
    else:
        print("还没有选择范围。请先运行 pick（浏览器勾选并确认），或在对话中确认后加 --yes。")
        return 2
    home = Path(args.home).expanduser() if args.home else Path(scope.get("home") or Path.home())
    st = load_state(out)
    now = dt.datetime.now(UTC)
    rng = args.range or scope.get("range", "auto")
    pick_mode = scope.get("mode") == "pick"
    only = (set(scope.get("tools", [])) | {p.split("::")[0] for p in scope.get("projects", [])}) if pick_mode else None
    proj_keys = set(scope.get("projects", [])) if pick_mode else None
    full_tools = set(scope.get("tools", []))
    # 导出前先裁一刀（只决定 agent-dump 要导出哪些会话，最终保留规则不变）：
    # 增量＝上次游标之后没动静的不导；基线且明确/超限只取最近 N 天时，更早的不导。
    ad_since = None
    if ad_bin() and scope.get("use_sessions", True):
        if st.get("baseline_done") and not args.rebuild:
            cur0 = parse_time(st.get("cursor"))
            if cur0 is not None:
                ad_since = cur0
        elif rng == "14":
            ad_since = now - dt.timedelta(days=args.days)
        elif rng == "auto":
            try:
                n = sum(1 for s in ad_list(home) if _ad_keep(s, only, proj_keys, full_tools))
                if n > args.max_sessions:
                    ad_since = now - dt.timedelta(days=args.days)
            except Exception:
                pass
    msgs = []
    if scope.get("use_sessions", True):
        msgs += [m for m in load_all(home, only, projects=proj_keys, full_tools=full_tools,
                                     since=ad_since) if in_scope(m, scope)]
    msgs += load_folders(scope.get("folders", []), "本地文件夹")
    if scope.get("inbox"):
        (out / "收集箱").mkdir(exist_ok=True)
        msgs += load_folders([str(out / "收集箱")], "收集箱")
    # 飞书（官方通道，v2.2）：scope.json feishu.enabled 时拉取。游标独立存放，
    # 因为飞书时间是本地口径（无时区标注），不能混进 AI 会话的 UTC 游标。
    fmsgs = []
    fs = scope.get("feishu") or {}
    if fs.get("enabled"):
        fcur = parse_time(st.get("feishu_cursor"))
        if fcur is None:
            fcur = now - dt.timedelta(days=args.days)  # 飞书侧首次基线同样只取最近 N 天
        only_chats = set(fs.get("chats") or []) or None
        fmsgs = [m for m in load_feishu(fcur, args.days, only_chats) if m.ts > fcur]
    ai_msgs = msgs          # AI 会话 / 文件夹 / 收集箱（游标与选择逻辑沿用原口径）
    msgs = msgs + fmsgs     # 合并后进素材包
    if not msgs:
        if (scope.get("feishu") or {}).get("enabled") and st.get("feishu_cursor"):
            print("没有新的会话，今天不需要更新。")  # 飞书增量拉完为空：正常，不是数据源缺失
            return 0
        print("所选数据源里还没有内容。收集箱为空的话，先往里放一个文件再试。")
        return 1
    if st.get("baseline_done") and not args.rebuild:
        cur = parse_time(st.get("cursor"))
        sel = [m for m in ai_msgs if cur is None or m.ts > cur] + fmsgs
        title, note = "会话素材包 · 增量", f"自上次（{cur.astimezone().strftime('%Y-%m-%d %H:%M') if cur else '—'}）以来的新会话"
    else:
        sessions = {(m.tool, m.session) for m in msgs}
        chars = sum(len(m.text) for m in msgs)
        if rng == "all" or (rng == "auto" and len(sessions) <= args.max_sessions and chars <= args.max_chars):
            sel, span = msgs, "全部历史"
        else:
            since = now - dt.timedelta(days=args.days)
            sel, span = [m for m in msgs if m.ts >= since], f"最近 {args.days} 天"
        reason = "" if rng != "auto" else f"（共 {len(sessions)} 个会话、约 {chars} 字；超过 {args.max_sessions} 个会话或 {args.max_chars} 字时只取最近 {args.days} 天）"
        title, note = "会话素材包 · 基线", f"首次整理：{span}{reason}"
    if not sel:
        print("没有新的会话，今天不需要更新。")
        return 0
    red = Redactor(home)
    p = write_pack(sel, out, red, title, note, scope.get("assistant", False), args.budget)
    if ai_msgs:
        st["cursor"] = max(m.ts for m in ai_msgs).isoformat()  # 只按 AI 会话口径推进
    if fmsgs:
        st["feishu_cursor"] = max(m.ts for m in fmsgs).isoformat()
    st["baseline_done"] = True
    st["runs"].append({"at": now.isoformat(), "type": "增量" if "增量" in title else "基线",
                       "messages": len(sel), "sessions": len({(m.tool, m.session) for m in sel}),
                       "pack": str(p.name), "redacted": dict(red.counts)})
    st["runs"] = st["runs"][-60:]
    save_state(out, st)
    n_user = sum(1 for m in sel if m.role == "user" or scope.get("assistant"))
    print(f"{title}：{len({(m.tool, m.session) for m in sel})} 个会话、{n_user} 条消息 → {p}")
    print("脱敏：" + red.report())
    print("收集引擎：" + engine_label())
    for n in ENGINE["notes"]:
        print("  提示：" + n)
    return 0


def _slug(name: str) -> str:
    s = re.sub(r"[^A-Za-z0-9]+", "-", name).strip("-").lower()
    return s or "my-workbench"


BUILD_SKILL = """---
name: {slug}
description: {name}。当我说「{phrase}」，或定时任务触发时使用：收集我选定的数据源，按固定模板生成{output_type}，交付后收集我的反馈并记住。
---

# {name}

> 由清见 workbench-coach 于 {date} 搭建。工作流 = 触发器 + 步骤链 + 输出物 + 反馈环，四样都在下面。
> 想改数据源、触发器或输出物：重新运行 `{py} "{script}" pick --out "{out}"`，再运行 build。

## 这套工作流解决什么

{scenario}

## ① 触发器

{trigger}

## ② 步骤链

0. **读偏好**：先读 `{out}/偏好.md`（没有就跳过）。里面是我以前的反馈，本次必须遵守；和下面的模板冲突时，以偏好为准。
1. **收集（脚本，本地完成，自动脱敏）**：运行
   `{py} "{script}" collect --out "{out}"`
   第一次运行建基线，之后只处理新内容；没有新内容就如实告诉我「今天没有新内容」，然后结束。
2. **读取**：只读取 `{out}/素材包/` 里最新的那一份素材包，不读取任何原始会话或原始文件。
3. **生成**：严格按「输出物」的模板生成，只写素材包里有的事实，推断要标「推测」。
4. **人做**：「我的判断」一节列出 1–3 个需要我自己决定的问题，不要替我回答。
5. **交付**：见「输出物 · 交付」。
6. **问反馈**：交付后问我一句「这份怎么样？回『好』，或直接说要改哪里」。

## ③ 输出物

- **是什么**：{output_type}
- **给谁看**：{audience}
- **模板**：`{template}`（每一块是一个小标题，顺序固定）
- **形式**：{format_line}
- **交付**：{delivery}
- **调用的技能**：{skills_line}

## ④ 反馈环

- 我回「好」：运行 `{py} "{script}" feedback --good --out "{out}"`。
- 我提了修改意见：运行 `{py} "{script}" feedback "改写后的规则" --out "{out}"`。它会记进 `偏好.md`，下次第 0 步就会读到。把意见改写成一条清楚的规则后再记（例如我说「旧项目别列了」，记成「超过 30 天没有动静的项目不列入」）。
- 每运行满 7 次，或我说「复盘一下」：运行 `{py} "{script}" feedback --review --out "{out}"`，根据结果给我 1–3 条调整建议：数据源要不要增减、触发时间要不要改、模板要不要加减一块。我同意后，重新 pick + build。

## 数据源（已在本地授权）

{sources}

## 规则

- 不读取我授权范围之外的任何内容。
- 输出简洁，一屏能看完的优先。
- 我说「停」就停止。
"""

TRIGGER_GUIDE = """# 触发器设置：{trigger_txt}

## 在 AI 工具里设置（推荐）

{tool_steps}

## 只想自动收集数据（不需要 AI）

收集这一步是普通脚本，可以交给系统定时，AI 那一步等你打开工具时再做：

- macOS / Linux（crontab -e 里加一行）：
  `{cron}`
- Windows（在命令提示符里运行一次）：
  `{schtasks}`

## 注意

- 定时任务需要电脑开着、AI 工具在运行；电脑经常关机，就改用手动：对 AI 说「{phrase}」。
- 想改数据源或触发器：重新运行 `{py} "{script}" pick --out "{out}"`，再运行 build。
"""


def _web_template(name: str, items: list) -> str:
    """网页简报模板：清见样式，纯内联 CSS、系统字体、无外部资源，可直接用浏览器打开或打印。"""
    e = html.escape
    secs = "\n".join(
        f'<section>\n  <h2>{e(it)}</h2>\n  <!-- 按素材包内容填写：用 <p> 或 <ul><li>；没有就写 <p class="none">无</p> -->\n  <p class="none">无</p>\n</section>'
        for it in items)
    return f"""<!doctype html>
<html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{e(name)} · YYYY-MM-DD</title>
<!-- 清见网页简报模板：只替换 <main> 里的内容和标题日期，不要改 <style>。 -->
<style>
:root{{--bg:#eef3f3;--paper:#fff;--ink:#14262b;--ink2:#4a5d62;--line:#d3dfe0;--teal:#0f6b6b;--teal-soft:#e2f0ef;--amber:#fff4d6;--amber-line:#e3c26a}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--ink);font:17px/1.7 "PingFang SC","Hiragino Sans GB","Microsoft YaHei",system-ui,sans-serif}}
main{{max-width:760px;margin:0 auto;padding:40px 24px 56px}}
header{{border-bottom:3px solid var(--ink);padding-bottom:14px;margin-bottom:8px}}
header h1{{font-size:30px;line-height:1.25;margin:0}}
header .date{{font-size:18px;color:var(--teal);font-weight:600;margin-top:4px}}
header .src{{font-size:14px;color:var(--ink2);margin-top:6px}}
section{{padding:18px 0;border-bottom:1px solid var(--line)}}
section h2{{font-size:20px;margin:0 0 8px;padding-left:12px;border-left:5px solid var(--teal)}}
section ul{{margin:0;padding-left:1.3em}} section li{{margin:4px 0}}
section p{{margin:6px 0}} .none{{color:var(--ink2)}}
.judge{{margin-top:22px;background:var(--amber);border:1px solid var(--amber-line);border-radius:12px;padding:16px 20px}}
.judge h2{{font-size:20px;margin:0 0 6px}} .judge ol{{margin:0;padding-left:1.4em}}
.fb{{margin-top:22px;font-size:15px;color:var(--ink2)}}
@media print{{body{{background:#fff}}main{{padding:0}}}}
</style>
<main>
<header>
  <h1>{e(name)}</h1>
  <div class="date">YYYY 年 M 月 D 日</div>
  <div class="src">来源：N 个工具、M 个会话（+ 收集箱 / 文件夹）；已遮挡 K 处敏感信息</div>
</header>
{secs}
<div class="judge">
  <h2>我的判断</h2>
  <ol><li>（需要我自己决定的问题，不替我回答）</li></ol>
</div>
<p class="fb">反馈：这份怎么样？回「好」，或直接说要改哪里。</p>
</main></html>
"""


def build(args):
    out = Path(args.out).expanduser() if args.out else default_out()
    scope_p, plan_p = out / "scope.json", (Path(args.plan) if args.plan else out / "方案.json")
    if not scope_p.exists():
        print("还没有选择数据源和触发器，请先运行 pick。")
        return 2
    scope = json.loads(scope_p.read_text(encoding="utf-8"))
    plan = json.loads(plan_p.read_text(encoding="utf-8")) if plan_p.exists() else {}
    name = plan.get("name") or "我的个人工作台"
    trig = scope.get("trigger") or {"type": "manual", "phrase": "运行我的工作台"}
    phrase = trig.get("phrase") or f"运行{name}"
    so = scope.get("output") or {}
    output_type = so.get("type") or _out_field(plan, "类型", "每日工作纪要")
    items = so.get("items") or _out_items(plan)
    audience = so.get("audience") or _out_field(plan, "给谁看", "自己")
    delivery = so.get("delivery") or ["save"]
    src = []
    if scope.get("use_sessions", True):
        rng = {"auto": "自动（多则最近 14 天）", "14": "最近 14 天", "all": "全部历史"}.get(scope.get("range", "auto"), "自动")
        what = "全部工具、全部项目" if scope.get("mode") != "pick" else "、".join(scope.get("tools", []) + [p.split("::")[-1] for p in scope.get("projects", [])])
        src.append(f"- 本地 AI 会话：{what}；首次范围：{rng}；{'含' if scope.get('assistant') else '不含'} AI 回复")
    for fd in scope.get("folders", []):
        src.append(f"- 本地文件夹：`{Redactor(Path.home()).path(fd)}`")
    if scope.get("inbox"):
        src.append(f"- 收集箱：`{out / '收集箱'}`（手动丢进来的材料）")
    script = Path(__file__).resolve()
    py = "python" if os.name == "nt" else "python3"
    slug = _slug(plan.get("slug") or "") if plan.get("slug") else "my-workbench"
    t = trig.get("type")
    trig_line = f"{trigger_text(trig)}。" + ("" if t == "manual" else f"也可以随时对我说「{phrase}」手动运行。")
    wf = out / "工作流" / name
    wf.mkdir(parents=True, exist_ok=True)
    (out / "输出").mkdir(exist_ok=True)
    tpl = wf / "输出模板.md"
    tpl.write_text("\n".join(
        [f"# {name} · YYYY-MM-DD", "", "> 来源：N 个工具、M 个会话（+ 收集箱 / 文件夹）；已遮挡 K 处敏感信息", ""]
        + sum(([f"## {it}", "", "（按素材包内容填写；没有就写「无」）", ""] for it in items), [])
        + ["## 我的判断", "", "1. （需要我自己决定的问题，不替我回答）", "", "---", "",
           "**反馈**：这份怎么样？回「好」，或直接说要改哪里。"]) + "\n", encoding="utf-8")
    fmt = so.get("format", "md")
    if fmt == "html":
        web_tpl = wf / "网页模板.html"
        web_tpl.write_text(_web_template(name, items), encoding="utf-8")
        format_line = (f"网页简报。先按 `{tpl}` 写好 Markdown（反馈、推送都用它），再按 `{web_tpl}` 的版式生成同名的 .html："
                       "只替换 <main> 里的内容和标题日期，不改样式；不引入任何外部资源。")
    elif fmt == "page":
        brief = wf / "主页设计说明.md"
        brief.write_text(PAGE_BRIEF.format(name=name, output_type=output_type, audience=audience,
                         scenario=plan.get("scenario") or "", items="\n".join(f"- {it}" for it in items),
                         out=out, py=py, script=script), encoding="utf-8")
        format_line = (f"工作台主页。每次先按 `{tpl}` 写好 Markdown（反馈、推送都用它），再把同样的内容写成同名的 .json"
                       f"（结构见 `{brief}`），然后运行 `{py} \"{script}\" page --out \"{out}\"` 更新主页数据。"
                       f"主页 `{out / '工作台.html'}` 只在第一次、或我要求改版时按 `{brief}` 设计；平时只更新数据，不改页面。")
    else:
        format_line = "文字版（Markdown）"
    skills = [x for x in (scope.get("skills") or []) if skill_allowed(x)]
    skills_line = ("无" if not skills else "、".join(f"`{x}`" for x in skills)
                   + "。生成时参考这些技能的方法；结构和版式仍以模板为准。没装好就先不用，不要中断。")
    dl = f"保存为 `{out / '输出'}/YYYY-MM-DD.md`" + {"html": "（网页简报另存同名 .html）",
                                                      "page": "（另存同名 .json，并更新工作台主页）"}.get(fmt, "")
    if "wecom" in delivery:
        dl += f"；然后推送到企业微信群：`{py} \"{script}\" push \"{out}/输出/YYYY-MM-DD.md\"`（读取环境变量 WECOM_WEBHOOK；没有设置就只保存，并提醒我）"
    (wf / "SKILL.md").write_text(BUILD_SKILL.format(
        slug=slug, name=name, phrase=phrase, output_type=output_type, date=dt.date.today().isoformat(),
        scenario=plan.get("scenario") or "把我在各处的工作痕迹放进同一个上下文，每天看清自己在忙什么。",
        audience=audience, template=tpl, delivery=dl, format_line=format_line, skills_line=skills_line,
        sources="\n".join(src) or "- （未选择）", py=py, script=script, out=out,
        trigger=trig_line), encoding="utf-8")
    hh, mm = (trig.get("time") or "18:00").split(":")[:2]
    dow = {"周一": 1, "周二": 2, "周三": 3, "周四": 4, "周五": 5, "周六": 6, "周日": 0}.get(trig.get("weekday", "周五"), 5)
    cron = f"{int(mm)} {int(hh)} * * {dow if t == 'weekly' else '*'} {py} \"{script}\" collect --out \"{out}\""
    sch = (f'schtasks /Create /SC {"WEEKLY /D " + ["SUN","MON","TUE","WED","THU","FRI","SAT"][dow] if t == "weekly" else "DAILY"} '
           f'/TN "清见工作台收集" /TR "{py} \\"{script}\\" collect --out \\"{out}\\"" /ST {hh}:{mm}')
    tool_steps = (
        f"打开 WorkBuddy 或千问办公，对它说：\n\n> 把「{phrase}」设成定时任务：{trigger_text(trig)}执行，使用技能文件 `{wf / 'SKILL.md'}`。\n\n"
        "Codex、ZCode 等编程工具如果没有内置定时任务，用手动口令运行，或用下面的系统定时只做收集。"
        if t != "manual" else f"不需要设置。想运行时，在任意 AI 工具里说：「{phrase}」，并告诉它技能文件在 `{wf / 'SKILL.md'}`。")
    (wf / "触发器设置.md").write_text(TRIGGER_GUIDE.format(
        trigger_txt=trigger_text(trig), tool_steps=tool_steps, cron=cron, schtasks=sch, phrase=phrase,
        py=py, script=script, out=out), encoding="utf-8")
    if plan:
        (wf / "方案.json").write_text(json.dumps(plan, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"已搭建「{name}」：{wf}")
    print(f"  SKILL.md       这套工作流的说明书：触发器 + 步骤链 + 输出物 + 反馈环")
    print(f"  输出模板.md    输出物的固定结构：" + "、".join(items) + "、我的判断")
    if fmt == "html":
        print(f"  网页模板.html  网页简报的版式（清见样式，无外部资源）")
    if fmt == "page":
        print(f"  主页设计说明.md  工作台主页的设计要求和数据结构（版式由 AI 按你的内容设计）")
        page_data(out)
    print(f"  触发器设置.md  {trigger_text(trig)}")
    if skills:
        print("需要安装的技能（经用户确认后再装）：")
        for x in skills:
            print(f"  npx skills add {x} -g -y")
    print("下一步：运行一次 collect，然后让 AI 按这个 SKILL.md 生成第一份结果。")
    return 0


# ------------------------------------------------------------- 工作台主页 ----
PAGE_BRIEF = """# 工作台主页设计说明：{name}

主页是一个本地网页 `{out}/工作台.html`，用户每天打开它看结果。版式由你（AI）按这个人的内容设计；
内容全部来自数据文件，每次运行只更新数据，页面不用重写。

## 这个人

- 场景：{scenario}
- 输出物：{output_type}，给{audience}看
- 固定的几块（主页要突出这些，顺序可以按重要程度调整）：
{items}

## 必须遵守

1. 单个文件 `{out}/工作台.html`，用 `<script src="工作台数据.js"></script>` 读取数据（变量 `window.WORKBENCH`）。
   不要用 fetch 或 XMLHttpRequest：双击打开（file://）时它们读不到本地文件。
2. 不引入任何外部资源：不用 CDN、网络字体、网络图片、统计脚本；页面不发起任何网络请求。字体用系统字体。
3. 页面里不写死任何具体内容：日期、要点、判断都从数据里取，这样每次运行后刷新页面就是最新的。
4. 数据为空、某一块没有内容、只有一天的数据时，页面都要正常显示，并给出一句提示。
5. 页面上可以勾选的东西（例如「我的判断」已处理），状态存在 localStorage，读写都要包在 try/catch 里；
   清掉也不影响内容。不要尝试把数据写回文件。
6. 每一块旁边放一个「改这里」按钮：点击后把一句反馈（例如「『今日要点』这一块：」）复制到剪贴板，
   提示用户粘贴回 AI 工具说明要怎么改。复制失败时，改为选中这句话让用户手动复制。
7. 手机宽度也能看；支持打印；键盘可以操作。
8. 安装了设计类技能（例如 frontend-design）就按它的方法设计；版式要贴合这个人的内容，不要套通用模板。

## 建议的模块（按需取舍）

- 今天：最新一次结果，按上面的几块展示，顶部一句话总结
- 我的判断：需要用户自己拍板的事，可勾选
- 最近几天：时间线，点开看历史（每条都有对应的 .md 文件路径）
- 它记住的偏好：来自 偏好.md，让用户看到「越用越懂我」
- 运行状态：数据源、触发器、上次运行时间、累计运行次数、遮挡了多少处敏感信息

## 数据结构（工作台数据.js，由脚本生成，不要手改）

```
window.WORKBENCH = {{
  "name": "工作台名字", "updated": "生成时间",
  "blocks": ["固定的几块小标题"],
  "trigger": "每天 18:00", "sources": ["本地 AI 会话（全部工具）", "收集箱"],
  "runs": [  // 新的在前，最多 60 次
    {{"date": "YYYY-MM-DD", "title": "…", "summary": "一句话",
     "sections": [{{"title": "块名", "items": ["…"]}}],
     "judgments": ["需要我决定的问题"],
     "stats": {{"tools": 3, "sessions": 12, "redacted": 4}},
     "md": "输出/YYYY-MM-DD.md"}}
  ],
  "prefs": ["偏好规则"], "feedback": {{"good": 3, "edits": 2}},
  "state": {{"runs": 12, "last_run": "…"}}
}}
```

每次运行写的 `输出/YYYY-MM-DD.json` 就是 runs 里的一项（date、title、summary、sections、judgments、stats），
写完运行：`{py} "{script}" page --out "{out}"`。
"""

_EXTERNAL = re.compile(r"""(?:src|href)\s*=\s*["']?\s*(?:https?:)?//|@import\s|url\(\s*["']?\s*(?:https?:)?//|\bfetch\s*\(|XMLHttpRequest""", re.I)


def page_data(out: Path) -> Path:
    """把 输出/*.json、偏好、反馈和运行状态汇总成 工作台数据.js（统一再脱敏一遍）。"""
    red = Redactor(Path.home())

    def clean(v):
        if isinstance(v, str):
            return red(v)
        if isinstance(v, list):
            return [clean(x) for x in v]
        if isinstance(v, dict):
            return {k: clean(x) for k, x in v.items()}
        return v

    runs, bad = [], []
    for f in sorted((out / "输出").glob("*.json"), reverse=True) if (out / "输出").exists() else []:
        try:
            r = json.loads(f.read_text(encoding="utf-8"))
            if not isinstance(r, dict) or not isinstance(r.get("sections", []), list):
                raise ValueError("格式不对")
        except (ValueError, OSError):
            bad.append(f.name)
            continue
        r.setdefault("date", f.stem)
        r.setdefault("md", f"输出/{f.stem}.md")
        runs.append(clean({k: r.get(k) for k in ("date", "title", "summary", "sections", "judgments", "stats", "md") if k in r}))
        if len(runs) >= 60:
            break
    scope = json.loads((out / "scope.json").read_text(encoding="utf-8")) if (out / "scope.json").exists() else {}
    plan = json.loads((out / "方案.json").read_text(encoding="utf-8")) if (out / "方案.json").exists() else {}
    fb = out / "反馈.jsonl"
    rows = [json.loads(l) for l in fb.read_text(encoding="utf-8").splitlines() if l.strip()] if fb.exists() else []
    st = load_state(out)
    srcs = []
    if scope.get("use_sessions", True) and scope:
        srcs.append("本地 AI 会话" + ("（全部工具）" if scope.get("mode") != "pick" else "（勾选的工具和项目）"))
    srcs += [f"本地文件夹：{red.path(x)}" for x in scope.get("folders", [])]
    if scope.get("inbox"):
        srcs.append("收集箱")
    data = {
        "name": plan.get("name") or scope.get("plan") or "我的个人工作台",
        "updated": dt.datetime.now().strftime("%Y-%m-%d %H:%M"),
        "blocks": (scope.get("output") or {}).get("items", []),
        "trigger": trigger_text(scope["trigger"]) if scope.get("trigger") else "",
        "sources": srcs,
        "runs": runs,
        "prefs": [red(x) for x in load_prefs(out)],
        "feedback": {"good": sum(1 for r in rows if r.get("rating") == "good"), "edits": sum(1 for r in rows if r.get("text"))},
        "state": {"runs": len(st.get("runs", [])), "last_run": (st.get("runs") or [{}])[-1].get("at", "") if st.get("runs") else ""},
    }
    js = out / "工作台数据.js"
    body = json.dumps(data, ensure_ascii=False, indent=1).replace("</", "<\\/")
    js.write_text("// 由 workbench.py page 生成，请勿手改\nwindow.WORKBENCH = " + body + ";\n", encoding="utf-8")
    if bad:
        print("跳过格式不对的结果文件：" + "、".join(bad))
    return js


def page_cmd(args):
    out = Path(args.out).expanduser() if args.out else default_out()
    if not (out / "scope.json").exists():
        print("还没有选择数据源和触发器，请先运行 pick。")
        return 2
    js = page_data(out)
    n = js.read_text(encoding="utf-8").count('"date"')
    print(f"已更新主页数据：{js}（{n} 次结果）")
    home = out / "工作台.html"
    if not home.exists():
        briefs = sorted((out / "工作流").glob("*/主页设计说明.md")) if (out / "工作流").exists() else []
        hint = briefs[0] if briefs else "工作流/<名字>/主页设计说明.md"
        print(f"还没有主页：请按 {hint} 设计 {home}（只需要做一次）。")
        return 0
    text = home.read_text(encoding="utf-8", errors="replace")
    probs = []
    if "工作台数据.js" not in text:
        probs.append("没有读取 工作台数据.js，内容不会自动更新")
    hits = sorted(set(m.group(0).strip() for m in _EXTERNAL.finditer(text)))
    if hits:
        probs.append("引用了外部资源或发起网络请求：" + "、".join(hits[:5]))
    if probs:
        print("主页需要修改：\n  - " + "\n  - ".join(probs))
        return 1
    print(f"主页：{home}（用浏览器打开；建议设为书签）")
    return 0


# ------------------------------------------------------------- 反馈环 ----
def feedback(args):
    out = Path(args.out).expanduser() if args.out else default_out()
    out.mkdir(parents=True, exist_ok=True)
    fb = out / "反馈.jsonl"
    if args.review:
        rows = [json.loads(l) for l in fb.read_text(encoding="utf-8").splitlines() if l.strip()] if fb.exists() else []
        st = load_state(out)
        good = sum(1 for r in rows if r.get("rating") == "good")
        bad = [r for r in rows if r.get("text")]
        print(f"累计运行 {len(st.get('runs', []))} 次；反馈 {len(rows)} 条：满意 {good} 条，修改意见 {len(bad)} 条。")
        for r in bad[-10:]:
            print(f"  - {parse_time(r['at']).astimezone().date()}：{r['text']}")
        prefs = load_prefs(out)
        print(f"当前偏好规则 {len(prefs)} 条（{out / '偏好.md'}）。")
        print("请据此给出 1–3 条调整建议：数据源、触发器、输出物模板。")
        return 0
    outs = sorted((out / "输出").glob("*.md")) if (out / "输出").exists() else []
    text = (args.text or "").strip()
    rating = "good" if args.good else ("bad" if args.bad or text else "good")
    rec = {"at": dt.datetime.now(UTC).isoformat(), "rating": rating, "text": Redactor(Path.home())(text),
           "output": outs[-1].name if outs else None}
    with fb.open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    if text:
        pp = out / "偏好.md"
        if not pp.exists():
            pp.write_text("# 我的偏好\n\n来自每次结果后的反馈。工作台每次生成前都会读这里；不想要的规则直接删掉那一行。\n\n", encoding="utf-8")
        with pp.open("a", encoding="utf-8") as f:
            f.write(f"- {rec['text']}（{dt.date.today().isoformat()}）\n")
        print(f"已记下，下次生成会遵守：{rec['text']}")
    else:
        print("已记下：这份满意。")
    if (out / "工作台数据.js").exists():
        page_data(out)
    return 0


def push(args):
    """把一份结果推送到企业微信群机器人。地址只从环境变量 WECOM_WEBHOOK 读取。"""
    import urllib.request
    text = Path(args.file).read_text(encoding="utf-8")
    data = text.encode("utf-8")
    if len(data) > 4000:
        text = data[:3900].decode("utf-8", errors="ignore") + "\n\n……（内容过长已截断，完整版见工作台）"
    if args.dry_run:
        print("【试运行，不会发送】\n" + text)
        return 0
    url = os.environ.get("WECOM_WEBHOOK", "").strip()
    if not url.startswith("https://qyapi.weixin.qq.com/"):
        print("没有设置 WECOM_WEBHOOK 环境变量，本次只保存、不推送。")
        return 1
    req = urllib.request.Request(url, data=json.dumps({"msgtype": "markdown", "markdown": {"content": text}},
                                 ensure_ascii=False).encode("utf-8"), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as r:
        res = json.loads(r.read().decode("utf-8"))
    print("已推送到企业微信群。" if res.get("errcode") == 0 else f"推送失败：{res}")
    return 0 if res.get("errcode") == 0 else 1


# ---------------------------------------------------------- 其他子命令 ----
def detect(args):
    home = Path(args.home).expanduser() if args.home else Path.home()
    summ = summarize(load_all(home))
    feishu_note = None
    if lark_bin():
        a = feishu_auth()
        feishu_note = (f"已授权 {a['user']} · 可见 {len(feishu_chats())} 个群（connect feishu 接入）" if a["ok"]
                       else "lark-cli 已装、未授权（connect feishu 看两步指引）")
    if args.json:
        d = {k: {**v, "projects": len(v["projects"])} for k, v in summ.items()}
        if feishu_note:
            d["飞书(官方通道)"] = feishu_note
        print(json.dumps(d, ensure_ascii=False, indent=2))
        return 0
    if not summ:
        print("没有找到支持的 AI 工具本地会话。可尝试：discover（找新工具的存储位置）或 import（导入手动导出的记录）。")
        return 1
    print(f"收集引擎：{engine_label()}")
    for n in ENGINE["notes"]:
        print("  提示：" + n)
    print(f"在 {Redactor(home).path(str(home)) or '~'} 下找到：")
    for tool, d in sorted(summ.items()):
        print(f"  {tool:<12} {d['sessions']:>4} 个会话  {d['messages']:>6} 条消息  {d['first']} ～ {d['last']}  {len(d['projects'])} 个项目")
    if feishu_note:
        print(f"  飞书(官方)   {feishu_note}")
    return 0


DISCOVER_HINTS = ("qwen", "qianwen", "tongyi", "workbuddy", "codebuddy", "zcode", "kimi", "trae", "cursor", "doubao",
                  "claude", "codex", "gemini", "opencode", "deepseek", "lingma", "marscode", "cline", "aider")


def discover(args):
    home = Path(args.home).expanduser() if args.home else Path.home()
    bases = [home]
    for env in ("APPDATA", "LOCALAPPDATA"):
        if os.environ.get(env):
            bases.append(Path(os.environ[env]))
    bases += [home / "Library/Application Support", home / ".config", home / ".local/share"]
    red = Redactor(home)
    found = []
    for b in bases:
        if not b.is_dir():
            continue
        try:
            entries = list(b.iterdir())
        except OSError:
            continue
        for d in entries:
            if d.is_dir() and any(h in d.name.lower() for h in DISCOVER_HINTS):
                files = []
                for pat in ("**/*.jsonl", "**/*.sqlite", "**/*.db", "**/*.vscdb", "**/sessions*.json"):
                    try:
                        files += [f for f in d.glob(pat) if f.is_file()][:50]
                    except OSError:
                        pass
                files = sorted(set(files), key=lambda f: -f.stat().st_size)[:15]
                found.append((d, files))
    if not found:
        print("没有发现疑似 AI 工具的数据目录。")
        return 1
    print("疑似 AI 工具数据目录（只列文件名和大小，未读取内容）：")
    for d, files in found:
        print(f"\n[{red.path(str(d))}]")
        for f in files:
            print(f"   {f.stat().st_size / 1024:>9.1f} KB  {red.path(str(f))}")
    print("\n把确认是会话记录的路径告诉讲师，或按 README 的「新增工具」一节加到 source_table。")
    return 0


def do_import(args):
    src = Path(args.folder).expanduser()
    out = Path(args.out).expanduser() if args.out else default_out()
    msgs = []
    for f in sorted(src.rglob("*")):
        if not f.is_file():
            continue
        suf = f.suffix.lower()
        if suf == ".jsonl":
            msgs += list(parse_claude_like(f, "手动导入"))
        elif suf == ".json":
            msgs += list(parse_json_file(f, "手动导入"))
        elif suf in (".md", ".txt"):
            t = f.read_text(encoding="utf-8", errors="replace")
            msgs.append(Msg("手动导入", f.stem, str(src), fmtime(f), "user", t[:20000], str(f)))
    if not msgs:
        print("文件夹里没有可导入的 .md / .txt / .json / .jsonl 文件。")
        return 1
    red = Redactor(Path.home())
    p = write_pack(msgs, out, red, "会话素材包 · 手动导入", f"来自 {red.path(str(src))}", True, args.budget)
    print(f"已导入 {len(msgs)} 段内容 → {p}\n脱敏：{red.report()}")
    return 0


SELF_TEST = [
    ("我的 key 是 sk-proj-AbCdEfGhIjKlMnOpQrStUvWx123456", "OpenAI类密钥"),
    ("password=Hunter2024!", "密码/密钥赋值"),
    ("身份证 11010519491231002X 请保密", "身份证号"),
    ("手机 13812345678", "手机号"),
    ("卡号 6222 0212 3456 7890 128", None),
    ("https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=693a91f6-7xxx-4bc4-97a0-0ec2sifa5aaa", "企微机器人key"),
    ("postgres://admin:s3cret@10.0.0.5:5432/db", "连接串"),
    ("订单号 20261108123456789 不是身份证", None),
]


def redact_cmd(args):
    if args.self_test:
        ok = True
        for text, expect in SELF_TEST:
            r = Redactor()
            out = r(text)
            hit = expect is None or expect in r.counts
            ok &= hit
            print(("✓" if hit else "✗"), out)
        print("自检通过" if ok else "自检未通过")
        return 0 if ok else 1
    r = Redactor(Path.home())
    for f in args.files:
        p = Path(f)
        q = p.with_name(p.stem + "_脱敏" + p.suffix)
        q.write_text(r(p.read_text(encoding="utf-8", errors="replace")), encoding="utf-8")
        print(f"{p.name} → {q.name}")
    print("脱敏：" + r.report())
    return 0


def main(argv=None):
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", line_buffering=True)
        except (ValueError, OSError):
            pass
    ap = argparse.ArgumentParser(prog="workbench", description="清见 · 个人工作台：本地 AI 会话收集器 v" + VERSION)
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p):
        p.add_argument("--home", help="家目录（默认当前用户；彩排可指向示例数据）")
        p.add_argument("--out", help="工作台目录（默认 ~/清见工作台）")
        p.add_argument("--engine", choices=["auto", "agent-dump", "builtin"], default="auto",
                       help="收集引擎：auto=装了 agent-dump 就用它（推荐），builtin=只用内置解析")

    p = sub.add_parser("detect"); common(p); p.add_argument("--json", action="store_true"); p.set_defaults(fn=detect)
    p = sub.add_parser("connect"); common(p); p.add_argument("channel", choices=["feishu"],
        help="接入官方通道：feishu=飞书（需 lark-cli，见 README「能力扩展」）"); p.set_defaults(fn=connect_cmd)
    p = sub.add_parser("discover"); common(p); p.set_defaults(fn=discover)
    p = sub.add_parser("pick"); common(p)
    p.add_argument("--port", type=int, default=0); p.add_argument("--no-browser", action="store_true")
    p.add_argument("--timeout", type=int, default=600); p.add_argument("--model", default="你正在使用的 AI 工具")
    p.add_argument("--plan", help="AI 落地分析生成的方案文件（默认 工作台目录/方案.json）")
    p.set_defaults(fn=pick)
    p = sub.add_parser("build"); common(p); p.add_argument("--plan"); p.set_defaults(fn=build)
    p = sub.add_parser("feedback"); common(p); p.add_argument("text", nargs="?")
    p.add_argument("--good", action="store_true"); p.add_argument("--bad", action="store_true")
    p.add_argument("--review", action="store_true"); p.set_defaults(fn=feedback)
    p = sub.add_parser("page"); common(p); p.set_defaults(fn=page_cmd)
    p = sub.add_parser("push"); p.add_argument("file"); p.add_argument("--dry-run", action="store_true"); p.set_defaults(fn=push)
    p = sub.add_parser("collect"); common(p)
    p.add_argument("--yes", action="store_true", help="已在对话里确认范围和授权（无浏览器时用），默认全局")
    p.add_argument("--range", choices=["auto", "14", "all"], help="覆盖 scope 里的时间范围")
    p.add_argument("--days", type=int, default=14)
    p.add_argument("--max-sessions", type=int, default=40, help="自动模式：会话数超过它就只取最近 N 天")
    p.add_argument("--max-chars", type=int, default=300000, help="自动模式：总字数超过它就只取最近 N 天")
    p.add_argument("--budget", type=int, default=60000, help="素材包正文字数上限")
    p.add_argument("--rebuild", action="store_true", help="忽略游标，重新建基线")
    p.set_defaults(fn=collect)
    p = sub.add_parser("import"); common(p); p.add_argument("folder"); p.add_argument("--budget", type=int, default=60000)
    p.set_defaults(fn=do_import)
    p = sub.add_parser("redact"); p.add_argument("files", nargs="*"); p.add_argument("--self-test", action="store_true")
    p.set_defaults(fn=redact_cmd)
    a = ap.parse_args(argv)
    ENGINE["name"] = getattr(a, "engine", "auto")
    if a.cmd == "collect" and a.range == "14":
        a.days = 14
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
