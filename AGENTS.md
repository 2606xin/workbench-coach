# 给 AI 助手的引导（AGENTS.md）

用户想在**你**这里搭建个人工作台/工作流时（例如说「用 workbench-coach 帮我搭个人工作台」「使用这个项目搭建我的个人工作流」，或只丢来一个 GitHub 链接 +「搭工作台」）：

1. **先读本目录的 `SKILL.md`，严格按它执行**——那是一份五步教练流程（一次一问的引导 → 落地分析 → 本机弹出选择页 → 搭建 → 反馈环），不要自由发挥、不要跳步。
2. 脚本：`scripts/workbench.py`（只用 Python 标准库）。跑之前先自检：`python3 scripts/test_workbench.py` 应显示「全部通过」。
3. 如果本目录是从 GitHub 克隆的且用户还没 clone：先 `git clone https://github.com/2606xin/workbench-coach.git` 并把工作目录切进去，再从第 1 步开始。
4. 新用户 30 秒上手说明见 `快速上手.md`；安全设计见 `README.md`。
