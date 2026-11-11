# 个人工作台搭建教练（workbench-coach）

**第 1 场「囤了 Token 不会用？」的唯一案例，也是学员带回家的交付物。**

> 🚀 **新来的？30 秒上手看 [快速上手.md](快速上手.md)**——一句话开始，AI 教练带你走完全程。

> **你的 AI 会话，第一次被放进同一个上下文。**

你在 Codex 里写脚本，在 WorkBuddy 里整理会议，在 ZCode 里做报销，在 Claude Code 里写小红书。每个工具都记得自己那一段，但没有一个工具知道你这一周在忙什么。这个技能是一位「搭建教练」，在学员自己的 AI 工具里，引导他用 5 步搭出属于自己的个人智能工作台：

| 步骤 | 谁来做 | 发生了什么 |
|---|---|---|
| 1. 苏格拉底问答 | AI 提问，学员回答 | 一次一问，追问「具体是哪一次」，找到真正重复的那件事 |
| 2. 落地分析 | AI | 评审三查（数据在哪 / 输出物说得清吗 / 触发器可行吗），不说「做不了」，给出三条出路，写成方案卡 |
| 3. 选择数据源 | 学员在本地页面勾选 | 页面顶部显示方案卡；可选本地 AI 会话、本地文件夹、收集箱；企微 / 飞书 / 钉钉标为 v2 |
| 4. 选择触发器、确认输出物 | 学员在同一页面勾选 | 每天定时、每周定时或一句手动口令；输出物包含哪几块、给谁看、怎么交付（保存 / 推送企业微信群） |
| 5. 搭出来 | 脚本 + AI | 脱敏收集 → 生成学员自己的工作台（SKILL.md、输出模板、触发器设置）→ 按模板跑出第一份结果 → 问反馈，写进偏好 |

搭出来的工作台四样齐全：**工作流 = 触发器 + 步骤链 + 输出物 + 反馈环**。

| 要素 | 具体是什么 |
|---|---|
| 触发器 | 每天 / 每周定时，或一句手动口令（`触发器设置.md` 里有各工具的设置方法） |
| 步骤链 | 读偏好 → 脱敏收集（首次建基线，之后只处理新内容）→ 按模板生成 → 人做判断 → 交付 → 问反馈 |
| 输出物 | `输出模板.md`：学员在页面上确认的几块内容 + 「我的判断」+ 反馈行；保存到 `输出/`，可选推送企业微信群 |
| 反馈环 | 每份结果后问一句；「好」记一次满意，修改意见改写成规则写进 `偏好.md`，下次收集时自动放进素材包顶部；每 7 次或说「复盘一下」时汇总，建议调整数据源、触发器、模板 |

---

## 一、快速开始

学员只需要在自己的 AI 工具（WorkBuddy、Codex、ZCode 等）里打开本技能目录，然后说：

> **用 workbench-coach 帮我搭个人工作台**

教练会自己完成检查环境、提问、分析、弹出页面和搭建。讲师彩排时可以手动跑一遍脚本部分：

```bash
python3 scripts/test_workbench.py                 # 自检：5 步里的脚本部分全部跑一遍，应显示「全部通过」
python3 scripts/workbench.py detect               # 这台电脑上有哪些 AI 会话（只计数）
cp 示例输入/方案_示例.json ~/清见工作台/方案.json   # 第 2 步的产物（正常由 AI 写）
python3 scripts/workbench.py pick                 # 第 3–4 步：浏览器里选数据源和触发器
python3 scripts/workbench.py collect              # 第 5 步：脱敏收集，生成素材包
python3 scripts/workbench.py build                # 第 5 步：生成学员自己的工作台 SKILL.md、输出模板
python3 scripts/workbench.py feedback "旧项目不列入"  # 反馈环：记下一条规则（--good 记满意，--review 复盘）
python3 scripts/workbench.py push 输出/日期.md --dry-run  # 交付：推送企业微信群（先试运行）
```

- Windows 把 `python3` 换成 `python` 或 `py -3`；需要 Python 3.8 以上。
- 收集引擎：先 `python3 -m pip install agent-dump`（见第三节）；没装也能跑，会自动改用内置解析。
- 没有 Python：教练会让学员二选一，要么装 Python，要么由 AI 直接读取（SKILL.md 末尾「无 Python 模式」）。
- 没有本地会话的电脑或彩排：命令加 `--home 示例输入/home --out 彩排工作台`，用虚构示例数据。注意 `示例输入/home` 里是 `.codex`、`.claude` 等隐藏文件夹，macOS 访达默认看不到。
- 后路：网页版 AI 的对话导出成 .md / .txt / .json 后，用 `import <文件夹>` 导入，或直接放进收集箱。

工作台默认建在 `~/清见工作台/`：

```
清见工作台/
├── 方案.json         ← 第 2 步：AI 的落地分析
├── scope.json        ← 第 3–4 步：数据源、触发器、授权时间
├── 收集箱/           ← 拿不到的数据，手动丢进来
├── 素材包/           ← 脱敏后的素材包（只有它会交给 AI）
├── 工作流/<名字>/    ← 第 5 步：SKILL.md（四要素）+ 输出模板.md + 触发器设置.md（选了网页简报时另有 网页模板.html）
├── 输出/             ← 每次运行的结果（选了工作台主页时另有同名 .json）
├── 工作台.html       ← 工作台主页（选了这个形式时才有；AI 按你的内容设计）
├── 工作台数据.js     ← 主页的数据，每次运行后由 page 命令更新
├── 偏好.md           ← 反馈环：从反馈里沉淀的规则，可以手动删改
├── 反馈.jsonl        ← 反馈环：每次反馈的原始记录（已脱敏）
└── state.json        ← 游标：上次处理到哪一刻；每次运行的遮挡统计
```

不想用了，删除定时任务和这个文件夹即可。脚本不会修改任何 AI 工具自己的数据。

参考成品（都由示例数据生成）：`方案_示例.json`（在示例输入里）、`会话素材包_基线_示例.md`、`我的工作台_SKILL示例.md`、`输出模板_示例.md`、`第一份结果_示例.md`、`偏好_示例.md`；另有 `基础盘纪要_示例.md` 和 `每日纪要_示例.md`，展示学员说不出场景时默认的「AI 会话纪要」长什么样。

## 1.5 能力扩展（11-10 新增，框架不变）

**不变的框架**：5 个步骤、页面四部分（①数据源 ②触发器 ③输出物 ④授权）、表单字段名、scope.json 已有字段、一次性 token 与 POST 校验、v2 灰卡、collect / build / feedback 的流程都没有动。下面三项只是**加选项**，不选就和原来完全一样。

| 新增 | 学员看到什么 | 落在哪里 |
|---|---|---|
| 选择页面改版 | 卡片分步、默认「全部 AI 会话」只显示一行汇总；选「只用我勾选的」才展开工具和项目（全选 / 半选 / 搜索）；底部常驻一句话总结；没勾同意按钮不可点；错误就地提示；提交后显示确认回执 | `scripts/workbench.py` 的 PICK_CSS / PICK_HTML |
| 网页简报 | ③输出物多一个「形式」：Markdown（默认）或网页简报 | scope.json `output.format`；build 时多生成 `网页模板.html`（清见配色、单文件、无外链、可打印） |
| 工作台主页 | ③输出物「形式」多一个「工作台主页」（推荐）：每天打开同一个本地网页 | 版式由 AI 按每个人的内容设计（`主页设计说明.md` 给出要求和数据结构）；每次运行写 `输出/日期.json`，`page` 命令汇总成 `工作台数据.js` 并检查主页没有外部资源 |
| 按场景找现成技能 | 第 2 步 AI 用 `npx skills find <关键词>` 找技能写进方案卡；页面③里可勾选；第 5 步确认后才 `npx skills add <id> -g -y` | 方案.json `skills_suggested`；scope.json `skills`；白名单见 `技能白名单.txt` |

技能白名单：默认只放行 `anthropics`、`vercel-labs` 两个来源；讲师审核后，在 `技能白名单.txt` 里一行加一个 `owner` 或 `owner/repo`。不在白名单里的技能在页面上显示为灰色、不可勾选，即使被硬塞进表单也会在写 scope.json 和 build 时被过滤掉。没有 Node 的电脑跳过这一步，不影响搭建。

## 1.6 官方通道接入（11-11 新增：飞书）

数据源不止本地 AI 会话——**飞书群消息已可直连**（走飞书官方 CLI [lark-cli](https://github.com/larksuite/cli)，只读：列群＋按日期拉消息；范围＝你的账号可见的群，平台安全模型决定不在的群读不到）：

```bash
npm install -g @larksuite/cli        # ① 装官方 CLI（需 Node.js）
lark-cli auth login --domain im      # ② 扫码授权（只勾「读消息」类权限）
python3 scripts/workbench.py connect feishu   # ③ 自检并写入 scope
```

之后每次 `collect` 自动拉取飞书增量（与 AI 会话并排进素材包，发言者按群友名字标注，同样过脱敏）；`detect` 会显示飞书授权状态。令牌由 lark-cli 存进系统钥匙串，本脚本不落任何凭证。未安装/未授权/过期都会自动降级为跳过并提示，不影响其他数据源。停用：scope.json 里 `feishu.enabled` 改 `false`。企业租户内的普通员工需管理员开应用权限，详见 `docs/v2设计_消息接入与文件记录.md` 第七、九节。

---

## 二、安全设计

和清见安全课的原则一致：**密钥不出门、最小授权、过程可审计。**

| 措施 | 怎么做 |
|---|---|
| 本地运行 | 收集、脱敏都在本机完成，脚本只用 Python 标准库，不联网 |
| 最小授权 | `pick` 在本机打开选择页面（只监听 127.0.0.1，带一次性随机口令），数据源、AI 会话的工具/项目、时间范围都由学员勾选；不勾的不读 |
| 明确同意 | 选择页面必须勾选「我已了解」才能保存；没有授权记录时 `collect` 拒绝运行 |
| 默认少取 | 默认只取「你说的话」，不取 AI 的回复；跳过工具调用结果、系统注入内容 |
| 自动遮挡 | 见下方脱敏清单；素材包顶部写明遮挡了几处，`state.json` 留存每次的遮挡统计 |
| 只读不改 | SQLite 数据库先复制一份再读，不锁、不改原库 |
| 先看后发 | 素材包是普通 Markdown，交给 AI 之前你可以先打开检查 |

### 脱敏清单（命中即替换为【已遮挡·类型】）

| 类型 | 例子 |
|---|---|
| 各类 API 密钥 | `sk-…`、`sk-ant-…`、`ghp_…`、`AKIA…`、阿里云 `LTAI…`、`AIza…` |
| 令牌与 Webhook | Bearer 令牌、JWT、企业微信机器人 key、飞书/钉钉机器人地址 |
| 密码赋值 | `password=`、`token:`、`密码：`、`密钥=` 后面的值 |
| 私钥与连接串 | `-----BEGIN PRIVATE KEY-----`、`mysql://用户:密码@主机` |
| 个人信息 | 身份证号（校验位验证）、银行卡号（Luhn 校验）、手机号、邮箱 |
| 电脑用户名 | 路径里的 `/Users/张三`、`C:\Users\张三` 统一换成 `~` |

规则在 `scripts/workbench.py` 顶部的 `REDACT_RULES`，加一行即可新增。改完运行 `python3 scripts/workbench.py redact --self-test`。

> 脱敏是「尽力遮挡」，不是百分之百。客户名称、合同金额这类没有固定格式的信息无法自动识别，所以选择页面默认让用户自己决定范围，素材包也建议先看一眼。

---

## 三、收集引擎选型

**结论：主引擎用开源项目 [agent-dump](https://github.com/xingkaixin/agent-dump)；它不支持的 WorkBuddy、CodeBuddy 用本技能的内置解析补充。**

本技能自己只做四件事：范围选择、脱敏、游标增量、生成素材包。「读懂每个工具的本地会话格式」这件最容易随版本变化的事，交给专门维护它的开源项目。

### 候选对比

| 项目 | 覆盖国内工具 | Windows | 安装 | 机器可读输出 | 许可证 | 结论 |
|---|---|---|---|---|---|---|
| **agent-dump** | ZCode、Kimi、Kimi Code、Qoder CN、DSH、DeepChat、Cherry Studio、MiniMax Code，以及 Codex、Claude Code、Cursor、Gemini CLI、OpenCode 等 | ✅ x64 | `pip install agent-dump`（预编译程序）/ uv / scoop / brew / npx | ✅ 统一 JSON（list / export） | MIT | **选用**：国内工具覆盖最全，和本技能同为 Python 生态，学员一行命令装好 |
| cass（coding_agent_session_search） | Kimi Code、Qwen Code；**不含** ZCode、WorkBuddy | ✅ | 单个程序，脚本 / scoop / brew / cargo | ✅ robot 模式（以搜索为主） | MIT + 附加条款 | 备选：社区最成熟（约 1.1k 星），但缺 ZCode，且导出接口以搜索为主 |
| ctx | 以海外编程工具为主，未列出国内工具 | ✅ | 安装脚本 | 部分 JSON | 页面未注明 | 不选：国内工具覆盖不明 |
| convx | 只支持 Cursor、Claude、Codex | — | pip | Markdown + JSON，带密钥脱敏 | — | 不选：覆盖太窄 |

已在本仓库用示例数据实测 agent-dump 1.2.8：Codex、Claude Code 会话被正确识别、按工作目录分项目，系统注入内容已被它过滤，导出的 JSON 统一为「角色 + 时间 + 文本 + 工作目录」，本技能的脱敏和增量在其之上正常工作（`scripts/test_workbench.py` 会两个引擎都测）。

### 各工具由谁负责

| 工具 | 收集引擎 | 说明 |
|---|---|---|
| Codex、Claude Code、Cursor、Gemini CLI、OpenCode | agent-dump | — |
| ZCode | agent-dump | 读取 macOS / Windows 默认数据库路径（Linux 无默认路径） |
| Kimi / Kimi Code、Qoder CN、DSH、DeepChat、Cherry Studio、MiniMax Code | agent-dump | — |
| WorkBuddy（中国版 `~/.workbuddy`、全球版 `~/.workbuddy-ai`） | 内置解析 | 目前没有开源项目支持；按其 `projects/` 下的 JSONL 读取，**属于实验性** |
| CodeBuddy | 内置解析 | 同上 |
| 千问办公桌面端 | 暂无 | 没有公开的本地存储说明，也没有开源项目支持；用 `discover` 查找，或把要点放进收集箱 |
| 网页版（豆包、千问、DeepSeek 等） | — | 本地没有数据；导出或复制成 .md 放进收集箱 |

### 引擎切换

- 默认 `--engine auto`：装了 agent-dump 就用它，没装就全部用内置解析。
- `--engine agent-dump`：强制使用，没装会提示安装命令。
- `--engine builtin`：只用内置解析（agent-dump 出问题时临时绕开）。
- `detect` 和 `collect` 的输出第一行会写明当前用的是哪个引擎、哪个版本；某个工具读取失败时会给出提示并跳过，不会中断。

### 仍然建议的一次冒烟测试

agent-dump 只覆盖到 ZCode 等工具的**默认安装路径**。正式上课前，用一台装了 ZCode 的 Windows 电脑运行一次 `python scripts/workbench.py detect`，看计数是否和实际对话量接近，即可。WorkBuddy 的内置解析是实验性的，同样看一眼 detect 的计数。

---

## 四、致谢

- [agent-dump](https://github.com/xingkaixin/agent-dump)（MIT）：本地会话读取与统一导出。
- 同类项目可作参考：[cass](https://github.com/Dicklesworthstone/coding_agent_session_search)、[ctx](https://ctx.rs)、[convx](https://github.com/pascalwhoop/convx)、[Callimachus](https://github.com/BetaBots-LLC/callimachus)。

## 许可

MIT，见 [LICENSE](LICENSE)。
