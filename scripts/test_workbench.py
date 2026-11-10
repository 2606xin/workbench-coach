#!/usr/bin/env python3
"""端到端自检：用示例数据把 5 步里的脚本部分完整跑一遍。
用法：在 workbench-coach 目录下运行  python3 scripts/test_workbench.py
新电脑上测试前先跑一次，确认脚本本身没问题。"""
import json, pathlib, re, shutil, subprocess, sys, tempfile, time, urllib.parse, urllib.request

HERE = pathlib.Path(__file__).resolve().parent
EX = HERE.parent / "示例输入"
HOME = EX / "home"
W = [sys.executable, "-I", str(HERE / "workbench.py")]
PLANTED = ["sk-proj-AbCdEf", "693a91f6-7a2c", "11010519491231002X", "13912345678", "13900002222", "/Users/xiaozhou"]
fails = []


def run(*a):
    r = subprocess.run(W + list(a), capture_output=True, text=True, encoding="utf-8")
    return r.returncode, r.stdout + r.stderr


with tempfile.TemporaryDirectory() as t:
    out = pathlib.Path(t) / "工作台"
    out.mkdir()
    # 第 1 步：未授权时必须拒绝
    code, _ = run("collect", "--home", str(HOME), "--out", str(out), "--engine", "builtin")
    if code != 2:
        fails.append("未授权时应拒绝收集")
    # 第 2 步：AI 写好的方案
    shutil.copy(EX / "方案_示例.json", out / "方案.json")
    # 第 3–4 步：页面选择数据源和触发器（模拟浏览器提交）
    p = subprocess.Popen(W + ["pick", "--home", str(HOME), "--out", str(out), "--no-browser", "--timeout", "30", "--engine", "builtin"],
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8")
    url = None
    for _ in range(100):
        line = p.stdout.readline()
        m = re.search(r"http://127\.0\.0\.1:\d+/\?t=\S+", line)
        if m:
            url = m.group(0)
            break
    if not url:
        fails.append("选择页面没有启动")
    else:
        noproxy = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        page = noproxy.open(url, timeout=10).read().decode("utf-8")
        if "小周的门店工作台" not in page or "选择触发器" not in page:
            fails.append("页面缺少方案或触发器部分")
        form = [("src", "ai_sessions"), ("src", "inbox"), ("mode", "all"), ("range", "auto"), ("trigger", "daily"),
                ("daily_time", "18:00"), ("weekday", "周五"), ("weekly_time", "18:00"), ("phrase", "运行我的工作台"),
                ("folders", ""), ("out_type", "每日工作纪要"), ("out_items", "今天做了什么\n门店数据异常\n待收尾"),
                ("out_aud", "自己"), ("consent", "1")]
        noproxy.open(url.replace("/?", "/submit?"), data=urllib.parse.urlencode(form).encode(), timeout=10).read()
        p.wait(timeout=15)
        scope = json.loads((out / "scope.json").read_text(encoding="utf-8"))
        if not (scope["use_sessions"] and scope["inbox"] and scope["trigger"]["type"] == "daily"
                and scope["output"]["items"] == ["今天做了什么", "门店数据异常", "待收尾"]):
            fails.append("scope.json 内容不对（数据源 / 触发器 / 输出物）")
    # 第 5 步：收集 + 搭建
    shutil.copy(EX / "收集箱" / "王姐微信要点.txt", out / "收集箱" / "王姐微信要点.txt")
    code, log = run("collect", "--out", str(out), "--engine", "builtin")
    packs = list((out / "素材包").glob("*.md"))
    text = packs[0].read_text(encoding="utf-8") if packs else ""
    if code != 0 or not packs:
        fails.append("基线收集失败：" + log)
    for s in PLANTED:
        if s in text:
            fails.append("素材包里出现了未遮挡的敏感信息：" + s)
    for proj in ("门店周报自动化", "xhs", "会议纪要", "报销预审", "收集箱"):
        if proj not in text:
            fails.append("素材包缺少：" + proj)
    code, log = run("build", "--out", str(out))
    sk = out / "工作流" / "小周的门店工作台" / "SKILL.md"
    if code != 0 or not sk.exists() or "name: xiaozhou-workbench" not in sk.read_text(encoding="utf-8"):
        fails.append("build 没有生成工作台 SKILL.md：" + log)
    if not (out / "工作流" / "小周的门店工作台" / "触发器设置.md").exists():
        fails.append("缺少触发器设置.md")
    tpl = out / "工作流" / "小周的门店工作台" / "输出模板.md"
    if not tpl.exists() or "## 门店数据异常" not in tpl.read_text(encoding="utf-8"):
        fails.append("输出模板没有按选择的输出物生成")
    skill_text = sk.read_text(encoding="utf-8") if sk.exists() else ""
    for part in ("① 触发器", "② 步骤链", "③ 输出物", "④ 反馈环"):
        if part not in skill_text:
            fails.append("工作台 SKILL.md 缺少：" + part)
    # 能力扩展：网页简报 + 技能白名单（只加选项，不改原流程）
    sp = out / "scope.json"
    sc = json.loads(sp.read_text(encoding="utf-8"))
    sc["output"]["format"] = "html"
    sc["skills"] = ["anthropics/skills@frontend-design", "someone/evil-repo@stealer"]
    sp.write_text(json.dumps(sc, ensure_ascii=False), encoding="utf-8")
    code, log = run("build", "--out", str(out))
    wf2 = out / "工作流" / "小周的门店工作台"
    sk2 = (wf2 / "SKILL.md").read_text(encoding="utf-8") if (wf2 / "SKILL.md").exists() else ""
    web = (wf2 / "网页模板.html").read_text(encoding="utf-8") if (wf2 / "网页模板.html").exists() else ""
    if "## 门店数据异常" not in tpl.read_text(encoding="utf-8") or "<h2>门店数据异常</h2>" not in web:
        fails.append("网页简报模板没有按输出物生成")
    if re.search(r"https?://", web.split("<!--")[0] + "".join(x.split("-->")[-1] for x in web.split("<!--")[1:])):
        fails.append("网页模板里出现了外部资源链接")
    if "frontend-design" not in sk2 or "evil-repo" in sk2 or "evil-repo" in log:
        fails.append("技能白名单没有生效：" + log)
    # 反馈环：意见要写进偏好，并出现在下一次素材包里；意见里的敏感信息也要遮挡
    run("feedback", "--good", "--out", str(out))
    run("feedback", "旧项目不列入，电话 13700001111 不要出现", "--out", str(out))
    prefs = (out / "偏好.md").read_text(encoding="utf-8") if (out / "偏好.md").exists() else ""
    if "旧项目不列入" not in prefs or "13700001111" in prefs:
        fails.append("反馈没有正确写入偏好（或没有脱敏）")
    # 增量：没有新内容
    code, log = run("collect", "--out", str(out), "--engine", "builtin")
    if "没有新的" not in log:
        fails.append("增量逻辑异常：" + log)
    # 增量：收集箱新增一个文件
    time.sleep(1.1)
    (out / "收集箱" / "新要点.txt").write_text("周四下午三点和中央厨房确认圣诞产能", encoding="utf-8")
    code, log = run("collect", "--out", str(out), "--engine", "builtin")
    if "增量" not in log:
        fails.append("收集箱新增文件后没有生成增量素材包：" + log)
    newest = max((out / "素材包").glob("*.md"), key=lambda p: p.stat().st_mtime).read_text(encoding="utf-8")
    if "## 我的偏好" not in newest or "旧项目不列入" not in newest:
        fails.append("下一次素材包没有带上偏好（反馈环没有闭合）")
    code, log = run("feedback", "--review", "--out", str(out))
    if "修改意见 1 条" not in log:
        fails.append("复盘汇总异常：" + log)
    code, _ = run("redact", "--self-test")
    if code != 0:
        fails.append("脱敏自检失败")

# agent-dump 主引擎（装了才测）
if shutil.which("agent-dump"):
    with tempfile.TemporaryDirectory() as t:
        out = pathlib.Path(t) / "工作台"
        code, log = run("detect", "--home", str(HOME), "--engine", "agent-dump")
        if "agent-dump" not in log or "Codex" not in log or "Claude Code" not in log or "WorkBuddy" not in log:
            fails.append("agent-dump 引擎识别异常：" + log)
        code, log = run("collect", "--home", str(HOME), "--out", str(out), "--yes", "--engine", "agent-dump")
        packs = list((out / "素材包").glob("*.md"))
        text = packs[0].read_text(encoding="utf-8") if packs else ""
        if code != 0 or not packs:
            fails.append("agent-dump 引擎收集失败：" + log)
        for s in PLANTED:
            if s in text:
                fails.append("agent-dump 引擎：素材包里出现了未遮挡的敏感信息：" + s)
        for proj in ("门店周报自动化", "xhs", "会议纪要"):
            if "项目：" + proj not in text:
                fails.append("agent-dump 引擎：素材包缺少项目 " + proj)
    print("agent-dump 主引擎：已测试")
else:
    print("agent-dump 主引擎：未安装，跳过（运行 pip install agent-dump 后再测）")

print("全部通过 ✓" if not fails else "未通过：\n- " + "\n- ".join(fails))
sys.exit(1 if fails else 0)
