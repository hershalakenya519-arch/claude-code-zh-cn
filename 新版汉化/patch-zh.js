// CC 原生二进制「看得见的文字」原地汉化 v2：只换完整字符串字面量，补齐空格放引号外
const L = require(process.env.TMPDIR + "/biolib.js");
const fs = require("fs");
const [,, binPath, jsonPath] = process.argv;
const M = JSON.parse(fs.readFileSync(jsonPath, "utf8"));
// 片段表：模板字符串里夹着 ${变量} 的文本段，没有引号包围，只能裸匹配。
// 要求 >=15 字节，足够独特才不会误伤更长字符串的子串。
const fragPath = jsonPath.replace(/\.json$/, "-frag.json");
const F = fs.existsSync(fragPath) ? JSON.parse(fs.readFileSync(fragPath, "utf8")) : {};
const data = Buffer.from(fs.readFileSync(binPath));
const hits = []; let done = 0; const miss = [];

for (const [en, zh] of Object.entries(M)) {
  const eb = Buffer.from(en, "utf8"), zb = Buffer.from(zh, "utf8");
  let n = 0;
  for (const q of ['"', "'", "`"]) {                    // 三种引号都试
    const needle = Buffer.from(q + en + q, "utf8");
    const repl   = Buffer.from(q + zh + q, "utf8");
    if (repl.length > needle.length) continue;
    const pad = Buffer.concat([repl, Buffer.alloc(needle.length - repl.length, 0x20)]);
    let i = data.indexOf(needle);
    while (i !== -1) { pad.copy(data, i); hits.push(i + 1); n++; i = data.indexOf(needle, i + 1); }
  }
  if (n === 0) miss.push(en); else done++;
}
// 字符串表：菜单真正读的是 \0英文\0 这份，不是源码里带引号的那份
let idone = 0;
for (const [en, zh] of Object.entries(M)) {
  const eb = Buffer.from(en, "utf8"), zb = Buffer.from(zh, "utf8");
  if (zb.length > eb.length) continue;
  const inner = Buffer.concat([zb, Buffer.alloc(eb.length - zb.length, 0x20)]);
  const needle = Buffer.concat([Buffer.from([0]), eb, Buffer.from([0])]);
  const repl   = Buffer.concat([Buffer.from([0]), inner, Buffer.from([0])]);
  let i = data.indexOf(needle), n = 0;
  while (i !== -1) { repl.copy(data, i); hits.push(i + 1); n++; i = data.indexOf(needle, i + 1); }
  if (n > 0) idone++;
}
console.log(`字符串表 ${idone} 条`);
// UTF-16LE 字符串表：以 0x0000 结尾的整句才换，避免截到更长描述里
let u16done = 0;
for (const [en, zh] of Object.entries(M)) {
  const e16 = Buffer.from(en, "utf16le"), z16 = Buffer.from(zh, "utf16le");
  if (e16.length < 20 || z16.length > e16.length) continue;
  const pad = Buffer.alloc(e16.length - z16.length);
  for (let i = 0; i < pad.length; i += 2) pad[i] = 0x20;
  const needle = Buffer.concat([e16, Buffer.from([0, 0])]);
  const repl   = Buffer.concat([z16, pad, Buffer.from([0, 0])]);
  let i = data.indexOf(needle), n = 0;
  while (i !== -1) { repl.copy(data, i); hits.push(i); n++; i = data.indexOf(needle, i + 1); }
  if (n > 0) u16done++;
}
console.log(`UTF-16 表 ${u16done} 条`);
// 片段替换（裸匹配，补齐空格直接跟在文本后面）
let fdone = 0;
for (const [en, zh] of Object.entries(F)) {
  const eb = Buffer.from(en, "utf8"), zb = Buffer.from(zh, "utf8");
  if (eb.length < 18) { console.log("片段太短，跳过:", en.slice(0,40)); continue; }
  if (zb.length > eb.length) { console.log("片段超长，跳过:", zh.slice(0,40)); continue; }
  const pad = Buffer.concat([zb, Buffer.alloc(eb.length - zb.length, 0x20)]);
  let i = data.indexOf(eb), n = 0;
  while (i !== -1) { pad.copy(data, i); hits.push(i); n++; i = data.indexOf(eb, i + 1); }
  if (n > 0) fdone++;
}
console.log(`片段表 ${Object.keys(F).length} 条 → 换掉 ${fdone} 条`);
fs.writeFileSync(binPath, data);
console.log(`翻译表 ${Object.keys(M).length} 条 → 换掉 ${done} 条，落点 ${hits.length} 处`);
if (miss.length) { console.log(`没找到完整字面量的 ${miss.length} 条:`); miss.slice(0,6).forEach(e=>console.log("   " + e.slice(0,62))); }

const e = L.extractFromELFFile(binPath);
const base = e.section.offset + e.sectionHeaderSize;
const list = L.getStringPointerContent(e.bunData, e.bunOffsets.modulesPtr);
const n2 = list.length / e.moduleStructSize;
const mods = [];
for (let i = 0; i < n2; i++) {
  const m = L.parseCompiledModule(list, i * e.moduleStructSize, e.moduleStructSize);
  if (m.contents && m.contents.length) mods.push({ i, enc: m.encoding, s: m.contents.offset, t: m.contents.offset + m.contents.length });
}
const need = new Set();
for (const h of hits) {
  const off = h - base;
  const m = mods.find(x => off >= x.s && off < x.t);
  if (m && m.enc !== 0) need.add(m.i);
}
const fd = fs.openSync(binPath, "r+");
for (const idx of need) fs.writeSync(fd, Buffer.from([0]), 0, 1, base + e.bunOffsets.modulesPtr.offset + idx * e.moduleStructSize + 48);
fs.closeSync(fd);
console.log(`源码区模块 ${need.size} 个，encoding 改为 UTF-8`);
