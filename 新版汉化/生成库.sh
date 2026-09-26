#!/data/data/com.termux/files/usr/bin/bash
# 把上级目录的 bun-binary-io.js 截掉 CLI 调度段、补上 module.exports，变成可 require 的库
set -euo pipefail
SRC="$(dirname "$0")/../bun-binary-io.js"
OUT="$(dirname "$0")/biolib.js"
LN=$(command grep -n '^const command = process.argv\[2\];' "$SRC" | cut -d: -f1)
head -n $((LN-1)) "$SRC" > "$OUT"
cat >> "$OUT" <<'JS'
module.exports = { rebuildBunData, repackELFFile, extractFromELFFile, detectModuleStructSize, parseCompiledModule, getStringPointerContent, parseStringPointer, isClaudeModule, detectBinaryFormat, SIZEOF_MODULE_OLD, SIZEOF_MODULE_NEW };
JS
echo "已生成 $OUT"
