#!/data/data/com.termux/files/usr/bin/bash
# 给 CC 原生二进制打「看得见的文字」中文补丁（原地等长替换，不改文件大小）
# 用法: bash 一键汉化.sh <版本号>   例: bash 一键汉化.sh 2.1.278
set -euo pipefail
VER="${1:?用法: bash 一键汉化.sh <版本号>}"
D="$(cd "$(dirname "$0")" && pwd)"
V="$HOME/.local/share/claude/versions"
BIN="$V/$VER"
BAK="$V/$VER.zh-cn-backup"
[ -f "$BIN" ] || { echo "找不到 $BIN"; exit 1; }
[ -f "$BAK" ] || { cp "$BIN" "$BAK"; echo "已建干净备份 $BAK"; }
TMP="$V/$VER.zh-new"
cp "$BAK" "$TMP"                       # 永远从干净备份起步，避免二次打补丁
TMPDIR="$D" node "$D/patch-zh.js" "$TMP" "$D/zh.json"
# 2026-09-22:接上去的后台会话按两下 Ctrl+C 直接退出,不先落回会话总览(细节在 patch-exit.js 开头)
# 🔴 退出补丁认的是二进制里一个具体函数,CC 一升版极可能对不上。
# 以前这儿是「对不上就整个放弃」⇒ 把汉化一起拖下水,主人白等一趟。
# patch-exit.js 自己保证「有地方没对上就一处都不写」,所以它失败时 $TMP 仍是干净的已汉化版
# ⇒ 跳过它继续装,主人至少拿到中文界面;退出手感的账单独报,叫铃铃重新定位。
if TMPDIR="$D" node "$D/patch-exit.js" "$TMP"; then
  EXIT_PATCH=ok
else
  EXIT_PATCH=skip
  echo "⚠️  退出补丁没对上（这一版那个函数变了）—— 已跳过,汉化照常装。"
fi
P=/data/data/com.termux/files/usr
unset LD_PRELOAD
if "$P/glibc/lib/ld-linux-aarch64.so.1" --library-path "$P/glibc/lib" "$TMP" --version >/dev/null 2>&1; then
  mv "$TMP" "$BIN"; echo "✅ 装上了。退出 CC 重开即可看到中文。"
  if [ "$EXIT_PATCH" = skip ]; then
    echo "⚠️  但退出补丁这次没打上 —— 接上去的后台会话按两下 Ctrl+C 会先落回会话总览,得再退一轮。"
    echo "    要修:叫铃铃在 $VER 上重新定位那个脱离函数(记录在 家/客厅/干活记录/手机使用/Termux原生迁移.md)。"
  fi
else
  rm -f "$TMP"; echo "❌ 试跑失败，已放弃，原文件没动。"; exit 1
fi
