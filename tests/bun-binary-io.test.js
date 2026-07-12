const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const { execFileSync } = require("node:child_process");

const repoRoot = path.resolve(__dirname, "..");
const helperPath = path.join(repoRoot, "bun-binary-io.js");
const bunTrailer = Buffer.from("\n---- Bun! ----\n");

function createFakeMachOBinary(filePath, { trailerAtEof = false } = {}) {
  const prefix = Buffer.from([0xcf, 0xfa, 0xed, 0xfe, 0x00, 0x00, 0x00, 0x00]);
  const sectionPadding = Buffer.alloc(64, 0x41);
  const eofPadding = Buffer.alloc(64, 0x00);
  const parts = trailerAtEof
    ? [prefix, sectionPadding, eofPadding, bunTrailer]
    : [prefix, sectionPadding, bunTrailer, eofPadding];

  fs.writeFileSync(filePath, Buffer.concat(parts));
  fs.chmodSync(filePath, 0o755);
}

function createFakePeBinary(filePath) {
  const prefix = Buffer.from([0x4d, 0x5a, 0x90, 0x00]);
  const padding = Buffer.alloc(64, 0x50);
  fs.writeFileSync(filePath, Buffer.concat([prefix, padding, bunTrailer]));
  fs.chmodSync(filePath, 0o755);
}

function createBunSectionData(source, { encoding = 0 } = {}) {
  const strings = [
    Buffer.from("claude"),
    Buffer.from(source),
    Buffer.alloc(0),
    Buffer.alloc(0),
    Buffer.alloc(0),
    Buffer.alloc(0),
  ];
  const stringOffsets = [];
  let offset = 0;
  for (const value of strings) {
    stringOffsets.push({ offset, length: value.length });
    offset += value.length + 1;
  }

  const modulesListOffset = offset;
  const moduleStructSize = 52;
  const modulesListSize = moduleStructSize;
  offset += modulesListSize;

  const compileExecArgvOffset = offset;
  const compileExecArgvLength = 0;
  offset += 1;

  const offsetsOffset = offset;
  offset += 32;
  const trailerOffset = offset;
  offset += bunTrailer.length;

  const bunData = Buffer.alloc(offset, 0);
  strings.forEach((value, index) => {
    value.copy(bunData, stringOffsets[index].offset);
  });

  let pos = modulesListOffset;
  for (const pointer of stringOffsets) {
    bunData.writeUInt32LE(pointer.offset, pos);
    bunData.writeUInt32LE(pointer.length, pos + 4);
    pos += 8;
  }
  bunData.writeUInt8(encoding, pos);
  bunData.writeUInt8(0, pos + 1);
  bunData.writeUInt8(0, pos + 2);
  bunData.writeUInt8(0, pos + 3);

  pos = offsetsOffset;
  bunData.writeBigUInt64LE(BigInt(offsetsOffset), pos);
  pos += 8;
  bunData.writeUInt32LE(modulesListOffset, pos);
  bunData.writeUInt32LE(modulesListSize, pos + 4);
  pos += 8;
  bunData.writeUInt32LE(0, pos);
  pos += 4;
  bunData.writeUInt32LE(compileExecArgvOffset, pos);
  bunData.writeUInt32LE(compileExecArgvLength, pos + 4);
  pos += 8;
  bunData.writeUInt32LE(0, pos);
  bunTrailer.copy(bunData, trailerOffset);

  const sectionData = Buffer.alloc(8 + bunData.length);
  sectionData.writeBigUInt64LE(BigInt(bunData.length), 0);
  bunData.copy(sectionData, 8);
  return sectionData;
}

function readFakePeClaudeModuleEncoding(binaryPath) {
  const sectionData = fs.readFileSync(binaryPath).subarray(4);
  const bunDataLength = Number(sectionData.readBigUInt64LE(0));
  const bunData = sectionData.subarray(8, 8 + bunDataLength);
  const offsetsOffset = bunData.length - 32 - bunTrailer.length;
  const modulesListOffset = bunData.readUInt32LE(offsetsOffset + 8);
  const moduleEncodingOffset = modulesListOffset + 48;
  return bunData.readUInt8(moduleEncodingOffset);
}

function writeFakeNodeLief(root) {
  const moduleDir = path.join(root, "node_modules", "node-lief");
  fs.mkdirSync(moduleDir, { recursive: true });
  fs.writeFileSync(
    path.join(moduleDir, "index.js"),
    `
const fs = require("node:fs");
const path = require("node:path");

function createSection(binaryPath) {
  let content = fs.readFileSync(binaryPath).subarray(4);
  return {
    name: ".bun",
    size: BigInt(content.length),
    virtualSize: BigInt(content.length),
    get content() {
      return content;
    },
    set content(value) {
      content = Buffer.from(value);
      this.size = BigInt(content.length);
      this.virtualSize = BigInt(content.length);
    },
  };
}

exports.logging = { disable() {} };
exports.parse = function parse(binaryPath) {
  const section = createSection(binaryPath);
  return {
    format: "PE",
    sections() {
      return [section];
    },
    write(outputPath) {
      fs.writeFileSync(outputPath, Buffer.concat([Buffer.from([0x4d, 0x5a, 0x90, 0x00]), section.content]));
    },
  };
};
`
  );
}

function createFakeElfBinary(filePath) {
  const prefix = Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00]);
  const padding = Buffer.alloc(64, 0x42);
  fs.writeFileSync(filePath, Buffer.concat([prefix, padding, bunTrailer]));
  fs.chmodSync(filePath, 0o755);
}

// 结构完整的 ELF64 假二进制：.bun 节 + 尾部 .comment 节 + shstrtab + 节头表，
// 用于走通纯 JS 的 ELF extract/repack 节手术路径（不需要 node-lief）。
const FAKE_ELF_COMMENT = "fake-elf-tail-section";

function createFakeElfBunBinary(filePath, source) {
  const sectionData = createBunSectionData(source);
  const bunOffset = 4096;
  const commentData = Buffer.from(FAKE_ELF_COMMENT);
  const commentOffset = bunOffset + sectionData.length;
  const shstrtab = Buffer.from("\0.bun\0.comment\0.shstrtab\0", "latin1");
  const shstrtabOffset = commentOffset + commentData.length;
  const shoff = shstrtabOffset + shstrtab.length;

  const ehdr = Buffer.alloc(64);
  Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00]).copy(ehdr, 0);
  ehdr.writeUInt16LE(2, 0x10); // e_type = ET_EXEC
  ehdr.writeUInt16LE(62, 0x12); // e_machine = x86-64
  ehdr.writeUInt32LE(1, 0x14); // e_version
  ehdr.writeBigUInt64LE(0x400000n, 0x18); // e_entry
  ehdr.writeBigUInt64LE(64n, 0x20); // e_phoff
  ehdr.writeBigUInt64LE(BigInt(shoff), 0x28); // e_shoff
  ehdr.writeUInt16LE(64, 0x34); // e_ehsize
  ehdr.writeUInt16LE(56, 0x36); // e_phentsize
  ehdr.writeUInt16LE(1, 0x38); // e_phnum
  ehdr.writeUInt16LE(64, 0x3a); // e_shentsize
  ehdr.writeUInt16LE(4, 0x3c); // e_shnum
  ehdr.writeUInt16LE(3, 0x3e); // e_shstrndx

  const phdr = Buffer.alloc(56);
  phdr.writeUInt32LE(1, 0x00); // PT_LOAD
  phdr.writeUInt32LE(5, 0x04); // R+X
  phdr.writeBigUInt64LE(0n, 0x08); // p_offset
  phdr.writeBigUInt64LE(0x400000n, 0x10); // p_vaddr
  phdr.writeBigUInt64LE(0x400000n, 0x18); // p_paddr
  phdr.writeBigUInt64LE(BigInt(bunOffset + sectionData.length), 0x20); // p_filesz 覆盖 .bun
  phdr.writeBigUInt64LE(BigInt(bunOffset + sectionData.length), 0x28); // p_memsz
  phdr.writeBigUInt64LE(4096n, 0x30); // p_align

  function shdr({ nameOff, type, offset, size, addralign }) {
    const entry = Buffer.alloc(64);
    entry.writeUInt32LE(nameOff, 0);
    entry.writeUInt32LE(type, 4);
    entry.writeBigUInt64LE(BigInt(offset), 24);
    entry.writeBigUInt64LE(BigInt(size), 32);
    entry.writeBigUInt64LE(BigInt(addralign), 48);
    return entry;
  }

  const shdrs = Buffer.concat([
    shdr({ nameOff: 0, type: 0, offset: 0, size: 0, addralign: 0 }),
    shdr({ nameOff: 1, type: 1, offset: bunOffset, size: sectionData.length, addralign: 16 }),
    shdr({ nameOff: 6, type: 1, offset: commentOffset, size: commentData.length, addralign: 1 }),
    shdr({ nameOff: 15, type: 3, offset: shstrtabOffset, size: shstrtab.length, addralign: 1 }),
  ]);

  const file = Buffer.concat([
    ehdr,
    phdr,
    Buffer.alloc(bunOffset - 64 - 56),
    sectionData,
    commentData,
    shstrtab,
    shdrs,
  ]);
  fs.writeFileSync(filePath, file);
  fs.chmodSync(filePath, 0o755);
}

function readFakeElfSection(filePath, wantName) {
  const file = fs.readFileSync(filePath);
  const shoff = Number(file.readBigUInt64LE(0x28));
  const shentsize = file.readUInt16LE(0x3a);
  const shnum = file.readUInt16LE(0x3c);
  const shstrndx = file.readUInt16LE(0x3e);
  const strBase = shoff + shstrndx * shentsize;
  const strOffset = Number(file.readBigUInt64LE(strBase + 24));
  const strSize = Number(file.readBigUInt64LE(strBase + 32));
  const strtab = file.subarray(strOffset, strOffset + strSize);
  for (let i = 0; i < shnum; i++) {
    const base = shoff + i * shentsize;
    const nameOff = file.readUInt32LE(base);
    const end = strtab.indexOf(0, nameOff);
    const name = strtab.subarray(nameOff, end === -1 ? strtab.length : end).toString();
    if (name === wantName) {
      const offset = Number(file.readBigUInt64LE(base + 24));
      const size = Number(file.readBigUInt64LE(base + 32));
      return file.subarray(offset, offset + size);
    }
  }
  return null;
}

function runHelper(args, extraEnv = {}) {
  return execFileSync("node", [helperPath, ...args], {
    cwd: repoRoot,
    encoding: "utf8",
    env: {
      ...process.env,
      ...extraEnv,
    },
  }).trim();
}

function runHelperWithStatus(args, extraEnv = {}) {
  return require("node:child_process").spawnSync("node", [helperPath, ...args], {
    cwd: repoRoot,
    encoding: "utf8",
    env: {
      ...process.env,
      ...extraEnv,
    },
  });
}

test("detect treats Mach-O binaries with Bun trailer outside EOF as native-bun", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "cczh-bun-detect-"));
  const realBinary = path.join(tmp, "claude-real");
  const symlinkPath = path.join(tmp, "claude");
  const isolatedHome = path.join(tmp, "home");
  const isolatedPrefix = path.join(tmp, "npm-prefix");

  fs.mkdirSync(isolatedHome, { recursive: true });
  fs.mkdirSync(isolatedPrefix, { recursive: true });
  createFakeMachOBinary(realBinary, { trailerAtEof: false });
  fs.symlinkSync(realBinary, symlinkPath);
  const resolvedBinary = fs.realpathSync(realBinary);

  const output = runHelper(["detect", symlinkPath], {
    HOME: isolatedHome,
    npm_config_prefix: isolatedPrefix,
  });

  assert.equal(output, `native-bun:${resolvedBinary}`);
});

test("detect treats PE binaries with Bun trailer as native-bun", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "cczh-bun-detect-pe-"));
  const pePath = path.join(tmp, "claude.exe");

  createFakePeBinary(pePath);

  const output = runHelper(["detect", pePath], {
    HOME: path.join(tmp, "home"),
    npm_config_prefix: path.join(tmp, "npm-prefix"),
  });

  assert.equal(output, `native-bun:${fs.realpathSync(pePath)}`);
});

test("version falls back to package.json for npm-installed Windows native exe", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "cczh-bun-version-package-"));
  const packageRoot = path.join(tmp, "node_modules", "@anthropic-ai", "claude-code");
  const pePath = path.join(packageRoot, "bin", "claude.exe");

  fs.mkdirSync(path.dirname(pePath), { recursive: true });
  fs.writeFileSync(
    path.join(packageRoot, "package.json"),
    JSON.stringify({ name: "@anthropic-ai/claude-code", version: "2.1.150" })
  );
  createFakePeBinary(pePath);

  const output = runHelper(["version", pePath], {
    HOME: path.join(tmp, "home"),
    npm_config_prefix: path.join(tmp, "npm-prefix"),
  });

  assert.equal(output, "2.1.150");
});

test("detect returns npm cli.js path for npm-style installation layout", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "cczh-bun-detect-npm-"));
  const binDir = path.join(tmp, "prefix", "bin");
  const binPath = path.join(binDir, "claude");
  const cliPath = path.join(tmp, "prefix", "lib", "node_modules", "@anthropic-ai", "claude-code", "cli.js");

  fs.mkdirSync(path.dirname(cliPath), { recursive: true });
  fs.mkdirSync(binDir, { recursive: true });
  fs.writeFileSync(binPath, "#!/usr/bin/env node\n");
  fs.chmodSync(binPath, 0o755);
  fs.writeFileSync(cliPath, "// Version: 2.1.101\n");

  const output = runHelper(["detect", binPath], {
    HOME: path.join(tmp, "home"),
    npm_config_prefix: path.join(tmp, "npm-prefix"),
  });

  assert.equal(output, `npm:${fs.realpathSync(cliPath)}`);
});

test("detect returns unknown for plain files that are neither Bun binaries nor npm installs", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "cczh-bun-detect-unknown-"));
  const plainFile = path.join(tmp, "claude");
  fs.writeFileSync(plainFile, "#!/usr/bin/env bash\necho hi\n");
  fs.chmodSync(plainFile, 0o755);

  const output = runHelper(["detect", plainFile], {
    HOME: path.join(tmp, "home"),
    npm_config_prefix: path.join(tmp, "npm-prefix"),
  });

  assert.equal(output, "unknown");
});

test("detect treats ELF binaries with Bun trailer as native-bun", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "cczh-bun-detect-elf-"));
  const elfPath = path.join(tmp, "claude-elf");
  createFakeElfBinary(elfPath);

  const output = runHelper(["detect", elfPath], {
    HOME: path.join(tmp, "home"),
    npm_config_prefix: path.join(tmp, "npm-prefix"),
  });

  assert.equal(output, `native-bun:${fs.realpathSync(elfPath)}`);
});

test("check-deps reports ok for ELF binaries without node-lief", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "cczh-bun-elf-deps-"));
  const elfPath = path.join(tmp, "claude-elf");
  createFakeElfBunBinary(elfPath, "// Version: 2.1.207\nconst label = \"Bash command\";\n");

  const output = runHelper(["check-deps", elfPath], {
    HOME: path.join(tmp, "home"),
    npm_config_prefix: path.join(tmp, "npm-prefix"),
  });

  assert.equal(output, "ok");
});

test("extract, version, and repack work on ELF binaries without node-lief", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "cczh-bun-elf-repack-"));
  const binaryPath = path.join(tmp, "claude");
  const extractedPath = path.join(tmp, "extracted.js");
  const replacementPath = path.join(tmp, "replacement.js");
  const initialSource = "// Version: 2.1.207\nconst label = \"Bash command\";\n";
  // 变长替换：翻译后的中文比原文长，走「节后内容整体平移」的手术路径
  const replacementSource =
    "// Version: 2.1.207\nconst label = \"Bash 命令（未沙盒隔离，含更长的翻译文本用于扩节路径）\";\n";

  createFakeElfBunBinary(binaryPath, initialSource);
  fs.writeFileSync(replacementPath, replacementSource);

  const env = {
    HOME: path.join(tmp, "home"),
    npm_config_prefix: path.join(tmp, "npm-prefix"),
  };

  assert.equal(runHelper(["detect", binaryPath], env), `native-bun:${fs.realpathSync(binaryPath)}`);
  assert.equal(runHelper(["version", binaryPath], env), "2.1.207");
  assert.equal(runHelper(["extract", binaryPath, extractedPath], env), "ok");
  assert.equal(fs.readFileSync(extractedPath, "utf8"), initialSource);

  const repack = runHelperWithStatus(["repack", binaryPath, replacementPath], env);
  assert.equal(repack.status, 0, repack.stderr);
  assert.equal(repack.stdout.trim(), "ok");

  assert.equal(runHelper(["extract", binaryPath, extractedPath], env), "ok");
  assert.equal(fs.readFileSync(extractedPath, "utf8"), replacementSource);

  // 节后内容（.comment / shstrtab / 节头表）平移后必须完好
  assert.equal(String(readFakeElfSection(binaryPath, ".comment")), FAKE_ELF_COMMENT);

  // 变短替换：走「节缩小」路径，同样必须往返一致
  const shorterPath = path.join(tmp, "shorter.js");
  const shorterSource = "// Version: 2.1.207\nconst label = \"短\";\n";
  fs.writeFileSync(shorterPath, shorterSource);
  const shrink = runHelperWithStatus(["repack", binaryPath, shorterPath], env);
  assert.equal(shrink.status, 0, shrink.stderr);
  assert.equal(runHelper(["extract", binaryPath, extractedPath], env), "ok");
  assert.equal(fs.readFileSync(extractedPath, "utf8"), shorterSource);
  assert.equal(String(readFakeElfSection(binaryPath, ".comment")), FAKE_ELF_COMMENT);
});

test("resolve returns the real path for symlinks", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "cczh-bun-resolve-"));
  const realFile = path.join(tmp, "real");
  const symlinkPath = path.join(tmp, "link");

  fs.writeFileSync(realFile, "hello\n");
  fs.symlinkSync(realFile, symlinkPath);

  const output = runHelper(["resolve", symlinkPath]);
  assert.equal(output, fs.realpathSync(realFile));
});

test("check-deps returns ok or missing without crashing", () => {
  const output = runHelper(["check-deps"]);
  assert.match(output, /^(ok|missing)$/);
});

test("repack treats codesign signing and verification as hard requirements", () => {
  const helper = fs.readFileSync(helperPath, "utf8");

  assert.match(helper, /runCodesign\(\["-s", "-", "-f", outputPath\], "sign"\)/);
  assert.match(helper, /runCodesign\(\["--verify", "--strict", "--verbose=4", outputPath\], "verify"\)/);
  assert.doesNotMatch(helper, /Warning: codesign failed/);
});

test("helper has a format-dispatched PE extraction and repack path", () => {
  const helper = fs.readFileSync(helperPath, "utf8");

  assert.match(helper, /function extractFromPE\(LIEF, binaryPath\)/);
  assert.match(helper, /function extractNativeBun\(LIEF, binaryPath\)/);
  assert.match(helper, /function repackPE\(LIEF, peBinary, binPath, newBunBuffer, outputPath, sectionHeaderSize, section\)/);
  assert.match(helper, /case "PE":/);
  assert.doesNotMatch(helper, /only Mach-O \(macOS\) is supported in this version/);
});

test("extract, version, and repack can run through a PE node-lief adapter", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "cczh-bun-pe-repack-"));
  const binaryPath = path.join(tmp, "claude.exe");
  const extractedPath = path.join(tmp, "extracted.js");
  const replacementPath = path.join(tmp, "replacement.js");
  const fakeModuleRoot = path.join(tmp, "fake-node-path");
  const initialSource = "// Version: 2.1.150\nconst label = \"Bash command\";\n";
  const replacementSource = "// Version: 2.1.150\nconst label = \"Bash 命令\";\n";

  writeFakeNodeLief(fakeModuleRoot);
  fs.writeFileSync(
    binaryPath,
    Buffer.concat([Buffer.from([0x4d, 0x5a, 0x90, 0x00]), createBunSectionData(initialSource)])
  );
  fs.chmodSync(binaryPath, 0o755);
  fs.writeFileSync(replacementPath, replacementSource);

  const env = {
    NODE_PATH: path.join(fakeModuleRoot, "node_modules"),
    HOME: path.join(tmp, "home"),
    npm_config_prefix: path.join(tmp, "npm-prefix"),
  };

  assert.equal(runHelper(["version", binaryPath], env), "2.1.150");
  assert.equal(runHelper(["extract", binaryPath, extractedPath], env), "ok");
  assert.equal(fs.readFileSync(extractedPath, "utf8"), initialSource);

  const repack = runHelperWithStatus(["repack", binaryPath, replacementPath], env);
  assert.equal(repack.status, 0, repack.stderr);
  assert.equal(repack.stdout.trim(), "ok");

  assert.equal(runHelper(["extract", binaryPath, extractedPath], env), "ok");
  assert.equal(fs.readFileSync(extractedPath, "utf8"), replacementSource);
});

test("repack marks rewritten Claude source as UTF-8 module content", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "cczh-bun-utf8-repack-"));
  const binaryPath = path.join(tmp, "claude.exe");
  const replacementPath = path.join(tmp, "replacement.js");
  const fakeModuleRoot = path.join(tmp, "fake-node-path");

  writeFakeNodeLief(fakeModuleRoot);
  fs.writeFileSync(
    binaryPath,
    Buffer.concat([
      Buffer.from([0x4d, 0x5a, 0x90, 0x00]),
      createBunSectionData("// Version: 2.1.181\nconst label = \"Help\";\n", { encoding: 1 }),
    ])
  );
  fs.chmodSync(binaryPath, 0o755);
  fs.writeFileSync(replacementPath, "// Version: 2.1.181\nconst label = \"帮助\";\n");

  const repack = runHelperWithStatus(["repack", binaryPath, replacementPath], {
    NODE_PATH: path.join(fakeModuleRoot, "node_modules"),
    HOME: path.join(tmp, "home"),
    npm_config_prefix: path.join(tmp, "npm-prefix"),
  });

  assert.equal(repack.status, 0, repack.stderr);
  assert.equal(readFakePeClaudeModuleEncoding(binaryPath), 0);
});

test("hash returns sha256 for binary marker identity", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "cczh-bun-hash-"));
  const file = path.join(tmp, "claude");
  fs.writeFileSync(file, "native-binary-content\n");

  const output = runHelper(["hash", file]);
  const expected = crypto.createHash("sha256").update("native-binary-content\n").digest("hex");

  assert.equal(output, expected);
});
