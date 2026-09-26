// 接上去的后台会话:两下 Ctrl+C 直接退出 CC,不再先落回会话总览(2026-09-22 主人要的)
// 用法: node patch-exit.js <二进制>      (一键汉化.sh 在 patch-zh.js 之后自动调)
//
// ▍原版为什么要退两轮
//   后台会话里按两下 Ctrl+C(requestExit)跟按 ← 走的是同一个脱离函数,
//   外层总览收到「脱离」分不出是哪个键,一律回列表。
// ▍改三处(都是原地等长替换,短出来的补空格)
//   ① requestExit:后台会话里先给脱离函数发「要退出」的暗号,再照前台会话的路正常收工
//      ⇒ 会话真结束,不留一个闲着的后台进程吃运行内存;← 还走原路,不受影响
//   ② 脱离函数:收到暗号就把脱离消息写成 EKICKED:bye
//      · `claude attach` 那条路:消息以 E大写: 打头 ⇒ 不再重开会话总览,直接回终端
//      · 总览里那条路:EKICKED: 被剥掉,剩 bye 交给 ③
//   ③ 总览主循环:接会话回来收到 bye ⇒ 跳出循环 = 跟总览里按两下 Ctrl+C 一样退出
// ▍🔴 只改源码不算数:这版每个模块都带预编译字节码,CC 跑字节码。
//   实测把单个模块的字节码长度清零,CC 就改读源码,不崩(09-22 拿「exit」改成「EXIT」验过)。
//   所以改到的模块一律把字节码摘掉。
//
// ▍2026-09-26 改成【正则自适应】—— 以前写死混淆名,CC 一升版就全对不上
//   2.1.278 → 2.1.283 实测:结构一个字没变,变的全是压缩器随机起的短名
//   (WK→tY · Tt→vt · AX→jte · H7→poe · sit→$bt · Q4→t8 · this.#r→this.#n · Ae→We …)。
//   ⇒ 所以不认名字,只认【结构】:混淆名一律用 ([\w$]+) 捕获,原样搬进新写法。
//   两个版本都实测恰好匹配 1 处、都放得下。以后升版只要 CC 没改写这三段逻辑就自动适配。
//   ⚠ 240MB 二进制不整个转字符串(手机吃不住):先用固定锚点定位,只在附近 ±500 字节开窗跑正则。
const L = require(process.env.TMPDIR + "/biolib.js");
const fs = require("fs");
const bin = process.argv[2];
if (!bin) { console.error("用法: node patch-exit.js <二进制>"); process.exit(2); }

const SPECS = [
  ["后台会话按 Ctrl+C 退出:发暗号再收工",
   'requestExit=()=>{',
   /requestExit=\(\)=>\{let\{onDetachToCaller:(\w)\}=this\.#([\w$]+);if\(\1\)\{\1\(\);return\}if\(([\w$]+)\(\)\)\{([\w$]+)\(\);return\}/g,
   (m) => `requestExit=()=>{let{onDetachToCaller:${m[1]}}=this.#${m[2]};if(${m[1]}){${m[1]}();return}if(${m[3]}())${m[4]}(1);`],

  ["脱离函数认暗号",
   '{type:"detach-request",msg:',
   // v 挪进参数表省下「let 」4 个字节才放得下;调用方最多传一个参数,它永远是自己算的
   /function ([\w$]+)\((\w)\)\{if\(!([\w$]+)\(\)\)return;let (\w)=([\w$]+)\(\);if\(([\w$]+)\(\{type:"detach-request",msg:\4,broadcast:\2\?\.broadcast\}\)\)\{([\w$]+)\(\);return\}process\.stdout\.write\(([\w$]+)\(\4\)\),\7\(\)\}/g,
   (m) => `function ${m[1]}(${m[2]},${m[4]}){if(!${m[3]}())return;${m[4]}=${m[2]}>0?"EKICKED:bye":${m[5]}();${m[6]}({type:"detach-request",msg:${m[4]},broadcast:${m[2]}?.broadcast})||process.stdout.write(${m[8]}(${m[4]})),${m[7]}()}`],

  ["总览收到暗号就退出",
   '[FV-attach] attachJob returned after',
   /else\{if\(([\w$]+)\.msg\)([\w$]+)\.setError\(\1\.msg\);_\("fleet_view_open"\)\}([\w$]+)\("detach",([\w$]+)\.job\.state,\{attachDurationMs:Date\.now\(\)-([\w$]+)\}\),(\w)\(`\[FV-attach\] attachJob returned after \$\{Date\.now\(\)-([\w$]+)\}ms \\u2014 remounting list`\)\}/g,
   (m) => `else{if(${m[1]}.msg=="bye")break;if(${m[1]}.msg)${m[2]}.setError(${m[1]}.msg);_("fleet_view_open")}${m[3]}("detach",${m[4]}.job.state,{attachDurationMs:Date.now()-${m[5]}}),${m[6]}(\`[FV-attach] attach returned \${Date.now()-${m[7]}}ms\`)}`],
];

const data = fs.readFileSync(bin);

// 幂等:打过就整体跳过(暗号字面量是这份补丁独有的,原版 CC 没有)
if (data.includes(Buffer.from("EKICKED:bye", "latin1"))) {
  console.log("· 退出补丁早就打过了,跳过");
  process.exit(0);
}

const hits = [];
let bad = 0;
for (const [what, anchor, rx, mk] of SPECS) {
  const ab = Buffer.from(anchor, "latin1");
  const spots = [];
  let i = data.indexOf(ab);
  while (i !== -1) { spots.push(i); i = data.indexOf(ab, i + 1); }

  const found = new Map();   // 按偏移去重:相邻锚点的窗口会重叠
  for (const at of spots) {
    const lo = Math.max(0, at - 500);
    const win = data.slice(lo, at + 500).toString("latin1");
    rx.lastIndex = 0;
    for (const m of win.matchAll(rx)) found.set(lo + m.index, m);
  }

  if (found.size !== 1) {
    console.error(`✘ ${what}:结构匹配到 ${found.size} 处(要恰好 1 处)—— CC 这段逻辑改写了,这份补丁不能用`);
    bad++; continue;
  }
  const [off, m] = [...found.entries()][0];
  const ob = Buffer.from(m[0], "latin1"), nb = Buffer.from(mk(m), "latin1");
  if (nb.length > ob.length) {
    console.error(`✘ ${what}:新写法 ${nb.length} 字节比原文 ${ob.length} 长,放不下`);
    bad++; continue;
  }
  Buffer.concat([nb, Buffer.alloc(ob.length - nb.length, 0x20)]).copy(data, off);
  hits.push(off);
  console.log(`✔ ${what}(原 ${ob.length} → 新 ${nb.length},补 ${ob.length - nb.length} 空格)`);
}
if (bad) { console.error("有地方没对上,一处都不写,原文件没动"); process.exit(1); }
fs.writeFileSync(bin, data);

// 改到的模块摘掉字节码(模块结构里 bytecode 是第 4 个指针:偏移 24,长度在 +4)
const e = L.extractFromELFFile(bin);
const base = e.section.offset + e.sectionHeaderSize;
const list = L.getStringPointerContent(e.bunData, e.bunOffsets.modulesPtr);
const count = list.length / e.moduleStructSize;
const fd = fs.openSync(bin, "r+");
const seen = new Set();
for (const h of hits) {
  const off = h - base;
  for (let i = 0; i < count; i++) {
    const m = L.parseCompiledModule(list, i * e.moduleStructSize, e.moduleStructSize);
    if (!(m.contents && off >= m.contents.offset && off < m.contents.offset + m.contents.length)) continue;
    if (seen.has(i)) break;
    seen.add(i);
    const name = L.getStringPointerContent(e.bunData, m.name).toString();
    if (m.bytecode.length === 0) { console.log(`· ${name} 早就没有字节码了`); break; }
    fs.writeSync(fd, Buffer.alloc(4), 0, 4, base + e.bunOffsets.modulesPtr.offset + i * e.moduleStructSize + 24 + 4);
    console.log(`✔ ${name} 摘掉字节码(${(m.bytecode.length / 1048576).toFixed(1)}MB),改读源码`);
    break;
  }
}
fs.closeSync(fd);
if (seen.size !== 2) { console.error(`✘ 应该落在 2 个模块里,实际 ${seen.size} 个 —— 先别装`); process.exit(1); }
