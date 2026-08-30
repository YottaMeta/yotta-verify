# 更新日志

## v0.2.1 (2026-08-30)

- 措辞规范：清理「第三方」表述（改为外部 / 上游）；对外不提收费相关内容（移除 Pro 分层宣传）；
  统一「v0.2.0 腾讯式双视角」表述。

## v0.2.0 (2026-08-30)

安全家族检测能力增强（对齐腾讯云鼎 8 检测点 + 科恩 13 行为项）：

- **威胁捕获模型**：官方 8 检测点 taxonomy（供应链风险 / 命令执行风险 / 网络请求与数据外传 /
  文件操作与敏感路径访问 / Prompt 注入风险 / 远程脚本下载执行 / 可疑编码·混淆 / 其他安全风险）。
- **L3 MCP 工具面引擎（新增）**：识别 MCP server 工具集，追踪「工具参数 → 危险 sink」
  （spawnSync/execSync/任意文件读写），恶意 MCP 判 DO NOT INSTALL
  （修复差距实证：此前只报 info 权限汇总不判级）。
- **L2 数据流引擎（新增）**：argv 注入面 → 子进程 sink 无防护判 medium。
- **L1 判级修正**：新增 PathTraversal（路径穿越）/ MCPCommandExec（MCP 命令执行）/
  MCPFileAccess（MCP 任意文件读写）检测器（audit_rules 权威源，规则 54 → 61）。
- **报告升级v0.2.0 腾讯式双视角**：安全健康度评分（0-100）+ 威胁捕获模型视图（8 类逐类 verdict）+
  行为项（科恩式 13 项）+ 逐文件 verdict + 修复建议指南 + 内容 hash（text / JSON / Markdown）。
- **自扫与正例保障**：元信自扫 SAFE；yotta-memory v0.8.5（修复后）正例 SAFE；
  恶意 MCP 样例 DO NOT INSTALL；测试文件（构造样例）扫描跳过、发布包排除测试。
- **测试**：67 / 67 全绿（Python 3.8 / 3.13）。

## v0.1.1 (2026-08-29)
## v0.1.1 (2026-08-29)

维护性修复：

- 签名数据豁免：SIGNATURE_DATA_FILES 增加 hardening_rules.py（元安规则表），扫描元安
  （yotta-agent-hardening）仓库时不再把规则签名表误报为被测代码；与元安 S4 发布后家族
  规则表结构对齐（续18 遗留，2026-08-29 拍板升版）。

## v0.1.0 (2026-08-29)

初始发布：

- 定位：元信 —— 装前安全扫描器 + audited 徽章（信任层，市场主线 M1「已验证安全」）。
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
- 核心功能全开放（--pro 可选能力预留）。
- 测试：52 用例全绿（含自扫 dogfooding 无中高危）。
- 文档：SKILL.md + README 中英双版 + references（注入模式 / 报告模板 / 徽章说明）。
