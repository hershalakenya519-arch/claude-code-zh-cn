# claude-code-zh-cn

Claude Code CLI 中文本地化插件。

## 项目结构

- `patch-cli.sh` — CLI 硬编码文字 patch（被 install.sh 和 session-start hook 调用）
- `cli-translations.json` — 2225 条 UI 翻译对照表（英文→中文），patch-cli.sh 从此文件读取
- `install.sh` / `uninstall.sh` — 安装/卸载脚本
- `compute-patch-revision.sh` — patch 规则指纹计算，供 install.sh 和 session-start hook 共用
- `settings-overlay.json` — 合并到 settings.json 的中文设置（只含 language、spinnerTipsEnabled 等独有配置，**不含** verbs 和 tips 数据）
- `plugin/` — 插件（manifest、hooks、output-styles）
- `verbs/zh-CN.json` — 187 个 spinner 动词翻译（**唯一数据源**）
- `tips/zh-CN.json` — 41 条 spinner 提示翻译（**唯一数据源**）
- `CHANGELOG.md` — 版本变更记录

## 数据流

翻译数据**单一来源**，不允许重复维护：

- `verbs/zh-CN.json` 是动词的**唯一数据源**
- `tips/zh-CN.json` 是提示的**唯一数据源**
- `settings-overlay.json` **不重复存放** verbs 和 tips 数据
- `install.sh` 安装时从上述两个 JSON 文件动态读取，现场组装合并到 `~/.claude/settings.json`

**禁止**把 verbs 或 tips 的内容复制到 settings-overlay.json 里。如果要修改翻译，只改 verbs/ 或 tips/ 里的文件。

## 技术要点

- patch-cli.sh 使用**内容匹配**（匹配英文原文），不依赖变量名，跨版本稳定
- 从 `cli-translations.json` 批量读取翻译，按字符串长度**降序**替换（长字符串优先，避免子串冲突）
- ⚠️ **非 ASCII 字符有两种形态，取决于安装形态，别只按一种写翻译**：
  - **npm 版 cli.js** — `…` `·` `—` 都是**真实字符**（U+2026 等）
  - **原生二进制**（`bun-binary-io.js extract` 出来的 JS，主流安装形态）— 一律是**字面转义序列**：
    `·`→`\xB7`、`…`→`\u2026`、emoji→代理对 `\uD83D\uDCDD`，**十六进制字母大写**，≤0xFF 用 `\xXX`
  - 所以同一条翻译要**两种形态各存一条**，否则在原生二进制上静默失效（v2.7.6 前有 117 条这样哑火）
  - 新增前务必实测：`node bun-binary-io.js extract <二进制> /tmp/x.js`，再去 x.js 里 grep 确认形态
- ⚠️ **短词绝不能裸加进翻译表**：替换虽只在字符串字面量内做、且有词边界保护，但同名字面量遍布全库——
  实测 `Session` 260 处、`interactive` 178 处、`cwd` 147 处、`Model` 136 处、`Version` 89 处。
  UI 行标签一律走**结构化定向替换**（`installSettingsPanelLabelLocalization` 锚 `label:"X"`，每个仅 1-3 处）。
  尤其注意 `"interactive"` 另有一处是遥测 `publishContext` 标识，翻掉会污染上报数据
- ⚠️ **patch 输出的数字是「命中规则条数」不是「替换位置数」**（`if (hit) count++`，每条规则只计 1 次）。
  要量真实影响面：给候选发唯一哨兵串 → 跑一次 patch → 数哨兵出现次数
- node -e 在 bash 单引号里，用 Unicode 转义（`\uXXXX`）写中文，避免引号嵌套问题
- Hook 等技术术语保留英文（Hook 不是"钩子"，同 API、PR）
- Windows 兼容：NTFS 上 `fs.renameSync` 先 unlink 再 rename

## 版本发布流程

每完成一批有意义的改动后，按以下步骤发布新版本：

1. **升版本号** — 修改 `plugin/manifest.json` 里的 `version`（语义化版本）
2. **更新 CHANGELOG** — 在 `CHANGELOG.md` 顶部新增版本段落，分"新增/改进/修复"
3. **提交** — `git commit`，提交信息带上版本号
4. **打 tag** — `git tag vX.Y.Z`
5. **推送** — `git push origin main --tags`
6. **发 Release** — `gh release create vX.Y.Z --title "vX.Y.Z" --notes "变更摘要"`
7. **发布状态校验** — `bash scripts/preflight.sh --release-state`，确认 manifest / CHANGELOG / tag / GitHub Release 对齐
