#!/data/data/com.termux/files/usr/bin/bash
# 从 CC 二进制里捞出「所有斜杠命令的名字+描述」，跟翻译表比对，列出还没翻的。
# 用法: bash 找界面文字.sh <干净二进制路径>
# 🔴 四个方向都要捞：name 在前 / description 在前 / get description() / menuDescription。
# ⚠️ 拿干净备份跑；打过补丁的二进制里中文会被当成「还没翻」(已用 CJK 过滤兜底)。
set -euo pipefail
V="${1:?用法: bash 找界面文字.sh <二进制路径>}"
D="$(cd "$(dirname "$0")" && pwd)"
T="${TMPDIR:-/tmp}"
rg -a -o 'name:"[a-z][a-z0-9-]{1,24}",[^}]{0,140}?description:"[^"]{4,200}"' "$V" > "$T/_d1.txt" 2>/dev/null || true
rg -a -o 'description:"[^"]{4,200}",[^}]{0,140}?name:"[a-z][a-z0-9-]{1,24}"' "$V" > "$T/_d2.txt" 2>/dev/null || true
# 第三种写法:描述不是写死的字符串，是一段会算的代码 `get description(){ return 条件?"甲":"乙" }`
# 这种前两条正则完全抓不到，/login /init /fast /model 等都藏在这里。
rg -a -o 'name:"[a-z][a-z0-9-]{1,24}",get description\(\)\{[^}]{0,300}' "$V" > "$T/_d3.txt" 2>/dev/null || true
# 第四种:斜杠菜单给人看的是 menuDescription,不是 description(内置技能几乎全走这条)
rg -a -o 'menuDescription:"[^"]{4,240}"' "$V" > "$T/_d4.txt" 2>/dev/null || true
python3 - "$V" "$D/zh.json" "$T" <<'PY'
import re, json, sys, subprocess
V, ZH, T = sys.argv[1], sys.argv[2], sys.argv[3]
M = json.load(open(ZH))
descs = set()
for fn in ("_d1.txt", "_d2.txt", "_d3.txt", "_d4.txt"):
    try: lines = open(f"{T}/{fn}", encoding="utf-8", errors="replace")
    except FileNotFoundError: continue
    for line in lines:
        m = re.search(r'(?:menu)?description:"([^"]{4,240})"', line, re.I)
        if m: descs.add(m.group(1)); continue
        if fn == "_d3.txt":                       # 动态描述:把 return 后面的每个字符串都收进来
            for q in re.finditer(r'"([^"]{8,200})"', line):
                if not q.group(1).startswith(("get ", "name:")): descs.add(q.group(1))
def is_noise(d):
    # 代码片段、纯标识符(命令名/终端名)、明显的第三方库自我介绍，都不是给主人看的界面文字
    if "get description" in d or d.startswith(","): return True
    if re.fullmatch(r"[A-Za-z0-9_.-]+", d): return True
    if "Node.js" in d or "Google APIs" in d: return True
    if re.search(r"[一-鿿]", d): return True   # 已是中文 = 补丁打过了
    if len(re.findall(r"[A-Za-z]{3,}", d)) < 2: return True  # 少于两个英文词 = 代码碎片
    return False
missing = sorted(d for d in descs if d not in M and not is_noise(d))
print(f"命令描述共 {len(descs)} 条，已翻 {len(descs)-len(missing)} 条，还差 {len(missing)} 条")
if missing:
    print("\n还没翻的（出现>2处的别碰，会误伤代码）:")
    for d in missing:
        r = subprocess.run(["rg","-a","-o","-F",'"'+d+'"',V], capture_output=True, text=True)
        n = len([l for l in r.stdout.splitlines() if l.strip()])
        mark = "🔴多处" if n > 2 else "      "
        print(f"{mark}{n:>3}处 {len(d.encode()):>4}字节  {d[:80]}")
PY
