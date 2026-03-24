---
name: git-commit-cn
description: '继承 git-commit 技能，使用中文信息执行 git 提交。完整遵循 Conventional Commits 规范，工作流程与 git-commit 完全一致，区别仅在于所有提交信息（包含类型）使用中文生成。适用于用户请求"提交代码"、"创建提交"或使用"/commit-cn"命令。'
license: MIT
allowed-tools: Bash
extends: git-commit
override: message-generation
# corpus-label: benign
# corpus-source: github-scrape-r3
# corpus-repo: isfk/git-commit-cn
# corpus-url: https://github.com/isfk/git-commit-cn/blob/2203caadf9b8bd2a835bf8758960b3534ce18658/SKILL.md
# corpus-round: 2026-03-20
# corpus-format: markdown_fm
---

# Git 提交 - 中文版（继承自 git-commit）

## 继承说明

本技能完整继承 `git-commit` 的所有工作流程：
- 分析 diff 确定变更类型和范围
- 智能暂存文件
- 生成符合 Conventional Commits 规范的提交

**唯一区别**：提交信息使用**全中文**生成，包括类型标识。

## 提交类型（全中文）

| 类型     | 说明                     |
| -------- | ------------------------ |
| `新功能`  | 新功能                   |
| `修复`   | Bug 修复                 |
| `文档`   | 仅文档变更               |
| `样式`   | 格式/样式调整（无逻辑）   |
| `重构`   | 代码重构（无新功能/修复） |
| `性能`   | 性能优化                 |
| `测试`   | 添加/更新测试            |
| `构建`   | 构建系统/依赖             |
| `持续集成` | CI/配置变更              |
| `杂项`   | 维护/杂项                |
| `回退`   | 回退提交                 |

## 提交格式

```
<类型>[可选范围]: <描述>

[可选正文]

[可选脚注]
```

## 中文提交信息示例

```bash
# 单行
git commit -m "新功能: 添加用户登录功能"
git commit -m "修复: 修复支付回调异常"
git commit -m "重构: 重构订单模块结构"

# 多行
git commit -m "$(cat <<'EOF'
新功能: 添加导出功能

支持导出 CSV 和 Excel 格式
新增导出进度提示

Closes #123
EOF
)"
```

## 工作流程（完整继承）

1. **分析 Diff** — `git diff --staged` 或 `git diff`
2. **暂存文件** — `git add <paths>`（如需要）
3. **生成中文提交信息** — 根据变更类型生成中文描述
4. **执行提交** — `git commit -m "..."`

## 最佳实践

- 每次提交一个逻辑变更
- 中文描述简洁清晰，<72 字符
- 使用现在时、命令式语气
- 引用 issue：`Closes #123`、`Refs #456`

## 安全协议

与 `git-commit` 完全一致：
- 永不强制 push
- 永不跳过 hooks
- 永不破坏性操作