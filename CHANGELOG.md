# 更新日志

## v0.1.0 (2026-08-29)

初始发布：

- 定位：元信 —— 装前安全扫描器 + audited 徽章（商业化信任层，市场主线 M1「已验证安全」）。
- 引擎：零依赖（Python 3.8+ 标准库）装前安全扫描 CLI，四块检测：
  ① Prompt Injection 8 类 28 条规则（指令覆盖 / 角色伪造 / 编码指令 / 数据外传 / 分隔符逃逸 /
     工具自执行 / 隐藏意图 / 凭据采集）+ base64 编码指令启发式；
  ② 危险模式 54 条规则（与元安 audit_rules 同步副本：下载即执行 / 混淆 / 持久化 / 外传 /
     凭据窃取 / 网络调用 / 权限提升 / 社会工程）；
  ③ SKILL.md 完整性（frontmatter 必需字段 / name 一致 / 围栏平衡 / 占位符）；
  ④ 权限需求分析（网络 / 命令 / 写入 / 敏感读取，info 级提示）。
- verdict：SAFE TO INSTALL / REVIEW REQUIRED / INSTALL WITH CAUTION / DO NOT INSTALL；
  exit code 与元安 / 元审一致（0 / 1 / 2 / 3 / 4）。
- badge：audited 徽章（本地 SVG + shields.io URL），内容 = verdict + validate-skill +
  元安 / 元审 verdict + 版本 + 引擎测试数。
- report：SKILL VERIFY REPORT（Markdown / JSON）。
- gate：CI 装前闸门（--max-severity，默认 medium，超出即失败）。
- 免费核心全开放 + Pro 分层骨架（--pro --license <key>，待商业化落地）。
- 测试：52 用例全绿（含自扫 dogfooding 无中高危）。
- 文档：SKILL.md + README 中英双版 + references（注入模式 / 报告模板 / 徽章说明）。
