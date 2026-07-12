#!/usr/bin/env node
/**
 * bun-binary-io.js — Bun 原生二进制 I/O 工具
 *
 * 从 tweakcc (Piebald-AI/tweakcc) 的 nativeInstallation.ts 精简移植。
 * 支持 macOS (Mach-O)、Windows (PE) 与 Linux (ELF)，仍按平台版本窗口开放。
 * Mach-O / PE 依赖 node-lief；ELF 为纯 JS 节手术，不需要 node-lief。
 *
 * CLI 子命令：
 *   detect <claude-cmd>     → 输出 "npm:<path>" 或 "native-bun:<path>" 或 "unknown"
 *   extract <binary> <out>  → 提取内嵌 JS 到 <out>
 *   repack <binary> <js>    → 将修改后的 JS 写回二进制（macOS 含 codesign）
 *   version <binary>        → 输出二进制内嵌的版本号
 *   resolve <path>          → 输出 realpath（跨平台 symlink 解析）
 *   check-deps [binary]     → 检查依赖是否满足（ELF 不需要 node-lief，给定路径按格式判断）
 */

"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const os = require("os");
const { execSync, execFileSync } = require("child_process");

// ============================================================================
// 常量
// ============================================================================

const BUN_TRAILER = Buffer.from("\n---- Bun! ----\n");
const SIZEOF_OFFSETS = 32;
const SIZEOF_STRING_POINTER = 8;
const SIZEOF_MODULE_OLD = 4 * SIZEOF_STRING_POINTER + 4; // 36
const SIZEOF_MODULE_NEW = 6 * SIZEOF_STRING_POINTER + 4; // 52
const JS_SOURCE_ENCODING_UTF8 = 0;

// ============================================================================
// node-lief 加载
// ============================================================================

function loadNodeLief() {
  // 1. 直接 require
  try { return require("node-lief"); } catch {}
  // 2. npm root -g
  try {
    const globalRoot = execSync("npm root -g", { encoding: "utf8" }).trim();
    return require(path.join(globalRoot, "node-lief"));
  } catch {}
  return null;
}

// ============================================================================
// 二进制格式检测
// ============================================================================

function hasBunTrailer(filePath) {
  try {
    const stat = fs.statSync(filePath);
    if (stat.size < BUN_TRAILER.length) return false;
    const fd = fs.openSync(filePath, "r");
    const chunkSize = 1024 * 1024;
    const overlap = BUN_TRAILER.length - 1;
    const buf = Buffer.alloc(chunkSize + overlap);
    let carry = 0;
    let position = 0;

    try {
      while (position < stat.size) {
        const bytesRead = fs.readSync(fd, buf, carry, chunkSize, position);
        if (bytesRead <= 0) break;
        const searchLength = carry + bytesRead;
        if (buf.subarray(0, searchLength).includes(BUN_TRAILER)) return true;
        if (searchLength > overlap) {
          buf.copyWithin(0, searchLength - overlap, searchLength);
          carry = overlap;
        } else {
          carry = searchLength;
        }
        position += bytesRead;
      }
      return false;
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    return false;
  }
}

function detectBinaryFormat(filePath) {
  try {
    const magic = Buffer.alloc(4);
    const fd = fs.openSync(filePath, "r");
    fs.readSync(fd, magic, 0, 4, 0);
    fs.closeSync(fd);
    // Mach-O 64-bit little-endian
    if (magic[0] === 0xCF && magic[1] === 0xFA && magic[2] === 0xED && magic[3] === 0xFE) return "MachO64";
    // Mach-O 32-bit little-endian
    if (magic[0] === 0xCE && magic[1] === 0xFA && magic[2] === 0xED && magic[3] === 0xFE) return "MachO32";
    // ELF
    if (magic[0] === 0x7F && magic[1] === 0x45 && magic[2] === 0x4C && magic[3] === 0x46) return "ELF";
    // PE (Windows)
    if (magic[0] === 0x4D && magic[1] === 0x5A) return "PE";
    return "unknown";
  } catch {
    return "unknown";
  }
}

// ============================================================================
// 安装检测
// ============================================================================

function detectInstallation(claudeCmd) {
  // 1. 解析 symlink → realpath
  let realPath;
  try { realPath = fs.realpathSync(claudeCmd); } catch { return "unknown"; }

  // 2. 先判真实目标本身是不是 Bun 二进制（Codex 二审 #1）
  //    Mach-O（macOS）/ PE（Windows）/ ELF（Linux）都按 native-bun 处理
  const format = detectBinaryFormat(realPath);
  if ((format === "MachO64" || format === "MachO32" || format === "PE" || format === "ELF") && hasBunTrailer(realPath)) {
    return "native-bun:" + realPath;
  }

  // 3. 不是二进制 → 检查是否在 npm 布局中 (Unix: ../lib/node_modules/, Windows: node_modules/)
  const npmCli = path.resolve(path.dirname(realPath),
    "../lib/node_modules/@anthropic-ai/claude-code/cli.js");
  if (fs.existsSync(npmCli)) return "npm:" + npmCli;

  const npmCliWin = path.resolve(path.dirname(realPath),
    "node_modules/@anthropic-ai/claude-code/cli.js");
  if (fs.existsSync(npmCliWin)) return "npm:" + npmCliWin;

  // 4. npm 安装的原生二进制 (v2.x+)
  const npmExe = path.resolve(path.dirname(realPath),
    "node_modules/@anthropic-ai/claude-code/bin/claude.exe");
  if (fs.existsSync(npmExe)) {
    const exeFormat = detectBinaryFormat(npmExe);
    if ((exeFormat === "PE" || exeFormat === "MachO64" || exeFormat === "MachO32") && hasBunTrailer(npmExe)) {
      return "native-bun:" + npmExe;
    }
  }

  // 5. npm root -g 兜底
  try {
    const globalRoot = execSync("npm root -g", { encoding: "utf8" }).trim();

    const npmCli2 = path.join(globalRoot, "@anthropic-ai/claude-code/cli.js");
    if (fs.existsSync(npmCli2)) return "npm:" + npmCli2;

    const npmExe2 = path.join(globalRoot, "@anthropic-ai/claude-code/bin/claude.exe");
    if (fs.existsSync(npmExe2)) {
      const exeFormat2 = detectBinaryFormat(npmExe2);
      if ((exeFormat2 === "PE" || exeFormat2 === "MachO64" || exeFormat2 === "MachO32") && hasBunTrailer(npmExe2)) {
        return "native-bun:" + npmExe2;
      }
    }
  } catch {}

  return "unknown";
}

// ============================================================================
// Bun 数据解析（纯 Buffer 操作，基于 tweakcc）
// ============================================================================

function parseStringPointer(buffer, offset) {
  return {
    offset: buffer.readUInt32LE(offset),
    length: buffer.readUInt32LE(offset + 4),
  };
}

function getStringPointerContent(buffer, sp) {
  return buffer.subarray(sp.offset, sp.offset + sp.length);
}

function parseOffsets(buffer) {
  let pos = 0;
  const byteCount = buffer.readBigUInt64LE(pos);
  pos += 8;
  const modulesPtr = parseStringPointer(buffer, pos);
  pos += 8;
  const entryPointId = buffer.readUInt32LE(pos);
  pos += 4;
  const compileExecArgvPtr = parseStringPointer(buffer, pos);
  pos += 8;
  const flags = buffer.readUInt32LE(pos);
  return { byteCount, modulesPtr, entryPointId, compileExecArgvPtr, flags };
}

function detectModuleStructSize(modulesListLength) {
  const fitsNew = modulesListLength % SIZEOF_MODULE_NEW === 0;
  const fitsOld = modulesListLength % SIZEOF_MODULE_OLD === 0;
  if (fitsNew && !fitsOld) return SIZEOF_MODULE_NEW;
  if (fitsOld && !fitsNew) return SIZEOF_MODULE_OLD;
  // 歧义时优先新格式
  return SIZEOF_MODULE_NEW;
}

function isClaudeModule(moduleName) {
  return moduleName.endsWith("/claude") ||
    moduleName === "claude" ||
    moduleName.endsWith("/src/entrypoints/cli.js") ||
    moduleName === "src/entrypoints/cli.js";
}

function parseCompiledModule(buffer, offset, moduleStructSize) {
  let pos = offset;
  const name = parseStringPointer(buffer, pos); pos += 8;
  const contents = parseStringPointer(buffer, pos); pos += 8;
  const sourcemap = parseStringPointer(buffer, pos); pos += 8;
  const bytecode = parseStringPointer(buffer, pos); pos += 8;

  let moduleInfo, bytecodeOriginPath;
  if (moduleStructSize === SIZEOF_MODULE_NEW) {
    moduleInfo = parseStringPointer(buffer, pos); pos += 8;
    bytecodeOriginPath = parseStringPointer(buffer, pos); pos += 8;
  } else {
    moduleInfo = { offset: 0, length: 0 };
    bytecodeOriginPath = { offset: 0, length: 0 };
  }

  const encoding = buffer.readUInt8(pos); pos += 1;
  const loader = buffer.readUInt8(pos); pos += 1;
  const moduleFormat = buffer.readUInt8(pos); pos += 1;
  const side = buffer.readUInt8(pos);

  return { name, contents, sourcemap, bytecode, moduleInfo, bytecodeOriginPath, encoding, loader, moduleFormat, side };
}

function parseBunDataBlob(bunDataContent) {
  if (bunDataContent.length < SIZEOF_OFFSETS + BUN_TRAILER.length) {
    throw new Error("BUN data is too small");
  }

  // 验证 trailer
  const trailerStart = bunDataContent.length - BUN_TRAILER.length;
  if (!bunDataContent.subarray(trailerStart).equals(BUN_TRAILER)) {
    throw new Error("BUN trailer mismatch");
  }

  // 解析 Offsets
  const offsetsStart = bunDataContent.length - SIZEOF_OFFSETS - BUN_TRAILER.length;
  const bunOffsets = parseOffsets(bunDataContent.subarray(offsetsStart, offsetsStart + SIZEOF_OFFSETS));
  const moduleStructSize = detectModuleStructSize(bunOffsets.modulesPtr.length);

  return { bunOffsets, bunData: bunDataContent, moduleStructSize };
}

// Section format: [u32/u64 size header][bun data blob...]
function extractBunDataFromSection(sectionData) {
  if (sectionData.length < 4) throw new Error("Section data too small");

  // 尝试 u32 header（旧格式）
  const bunDataSizeU32 = sectionData.readUInt32LE(0);
  const expectedLengthU32 = 4 + bunDataSizeU32;

  // 尝试 u64 header（新格式）
  const bunDataSizeU64 = sectionData.length >= 8 ? Number(sectionData.readBigUInt64LE(0)) : 0;
  const expectedLengthU64 = 8 + bunDataSizeU64;

  let headerSize, bunDataSize;

  if (sectionData.length >= 8 && expectedLengthU64 <= sectionData.length && expectedLengthU64 >= sectionData.length - 4096) {
    headerSize = 8;
    bunDataSize = bunDataSizeU64;
  } else if (expectedLengthU32 <= sectionData.length && expectedLengthU32 >= sectionData.length - 4096) {
    headerSize = 4;
    bunDataSize = bunDataSizeU32;
  } else {
    throw new Error("Cannot determine section header format");
  }

  const bunDataContent = sectionData.subarray(headerSize, headerSize + bunDataSize);
  const parsed = parseBunDataBlob(bunDataContent);
  return { ...parsed, sectionHeaderSize: headerSize };
}

// ============================================================================
// 使用 node-lief 的提取/重打包
// ============================================================================

function extractFromMachO(LIEF, binaryPath) {
  LIEF.logging.disable();
  const binary = LIEF.parse(binaryPath);

  const bunSegment = binary.getSegment("__BUN");
  if (!bunSegment) throw new Error("__BUN segment not found");
  const bunSection = bunSegment.getSection("__bun");
  if (!bunSection) throw new Error("__bun section not found");

  return extractBunDataFromSection(bunSection.content);
}

function extractFromPE(LIEF, binaryPath) {
  LIEF.logging.disable();
  const binary = LIEF.parse(binaryPath);

  for (const section of binary.sections()) {
    try {
      const parsed = extractBunDataFromSection(section.content);
      return { ...parsed, section, binary };
    } catch {}
  }

  throw new Error("Bun section not found in PE binary");
}

function extractNativeBun(LIEF, binaryPath) {
  LIEF.logging.disable();
  const binary = LIEF.parse(binaryPath);

  switch (binary.format) {
    case "MachO": {
      const bunSegment = binary.getSegment("__BUN");
      if (!bunSegment) throw new Error("__BUN segment not found");
      const section = bunSegment.getSection("__bun");
      if (!section) throw new Error("__bun section not found");
      const parsed = extractBunDataFromSection(section.content);
      return { ...parsed, format: "MachO", binary, section, segment: bunSegment };
    }
    case "PE": {
      for (const section of binary.sections()) {
        try {
          const parsed = extractBunDataFromSection(section.content);
          return { ...parsed, format: "PE", binary, section };
        } catch {}
      }
      throw new Error("Bun section not found in PE binary");
    }
    default:
      throw new Error(`Unsupported native binary format: ${binary.format || "unknown"}`);
  }
}

function findClaudeModule(bunData, bunOffsets, moduleStructSize) {
  const modulesListBytes = getStringPointerContent(bunData, bunOffsets.modulesPtr);
  const count = Math.floor(modulesListBytes.length / moduleStructSize);

  for (let i = 0; i < count; i++) {
    const mod = parseCompiledModule(modulesListBytes, i * moduleStructSize, moduleStructSize);
    const moduleName = getStringPointerContent(bunData, mod.name).toString("utf-8");
    if (isClaudeModule(moduleName)) {
      return {
        module: mod,
        moduleName,
        contents: getStringPointerContent(bunData, mod.contents),
      };
    }
  }
  return null;
}

function rebuildBunData(bunData, bunOffsets, modifiedClaudeJs, moduleStructSize) {
  const modulesListBytes = getStringPointerContent(bunData, bunOffsets.modulesPtr);
  const count = Math.floor(modulesListBytes.length / moduleStructSize);

  // Phase 1: 收集所有模块数据
  const stringsData = [];
  const modulesMetadata = [];

  for (let i = 0; i < count; i++) {
    const mod = parseCompiledModule(modulesListBytes, i * moduleStructSize, moduleStructSize);
    const nameBytes = getStringPointerContent(bunData, mod.name);
    const moduleName = nameBytes.toString("utf-8");

    const isModifiedClaudeModule = Boolean(modifiedClaudeJs && isClaudeModule(moduleName));
    const contentsBytes = isModifiedClaudeModule
      ? modifiedClaudeJs
      : getStringPointerContent(bunData, mod.contents);
    const sourcemapBytes = getStringPointerContent(bunData, mod.sourcemap);
    const bytecodeBytes = getStringPointerContent(bunData, mod.bytecode);
    const moduleInfoBytes = getStringPointerContent(bunData, mod.moduleInfo);
    const bytecodeOriginPathBytes = getStringPointerContent(bunData, mod.bytecodeOriginPath);

    modulesMetadata.push({
      name: nameBytes, contents: contentsBytes, sourcemap: sourcemapBytes,
      bytecode: bytecodeBytes, moduleInfo: moduleInfoBytes, bytecodeOriginPath: bytecodeOriginPathBytes,
      encoding: isModifiedClaudeModule ? JS_SOURCE_ENCODING_UTF8 : mod.encoding,
      loader: mod.loader, moduleFormat: mod.moduleFormat, side: mod.side,
    });

    if (moduleStructSize === SIZEOF_MODULE_NEW) {
      stringsData.push(nameBytes, contentsBytes, sourcemapBytes, bytecodeBytes, moduleInfoBytes, bytecodeOriginPathBytes);
    } else {
      stringsData.push(nameBytes, contentsBytes, sourcemapBytes, bytecodeBytes);
    }
  }

  const stringsPerModule = moduleStructSize === SIZEOF_MODULE_NEW ? 6 : 4;

  // Phase 2: 计算布局
  let currentOffset = 0;
  const stringOffsets = [];
  for (const s of stringsData) {
    stringOffsets.push({ offset: currentOffset, length: s.length });
    currentOffset += s.length + 1; // +1 null terminator
  }

  const modulesListOffset = currentOffset;
  const modulesListSize = modulesMetadata.length * moduleStructSize;
  currentOffset += modulesListSize;

  const compileExecArgvBytes = getStringPointerContent(bunData, bunOffsets.compileExecArgvPtr);
  const compileExecArgvOffset = currentOffset;
  const compileExecArgvLength = compileExecArgvBytes.length;
  currentOffset += compileExecArgvLength + 1;

  const offsetsOffset = currentOffset;
  currentOffset += SIZEOF_OFFSETS;
  const trailerOffset = currentOffset;
  currentOffset += BUN_TRAILER.length;

  // Phase 3: 写入
  const newBuf = Buffer.allocUnsafe(currentOffset);
  newBuf.fill(0);

  let stringIdx = 0;
  for (const { offset, length } of stringOffsets) {
    if (length > 0) stringsData[stringIdx].copy(newBuf, offset, 0, length);
    newBuf[offset + length] = 0;
    stringIdx++;
  }

  if (compileExecArgvLength > 0) {
    compileExecArgvBytes.copy(newBuf, compileExecArgvOffset, 0, compileExecArgvLength);
    newBuf[compileExecArgvOffset + compileExecArgvLength] = 0;
  }

  for (let i = 0; i < modulesMetadata.length; i++) {
    const meta = modulesMetadata[i];
    const base = i * stringsPerModule;
    const modStruct = {
      name: stringOffsets[base], contents: stringOffsets[base + 1],
      sourcemap: stringOffsets[base + 2], bytecode: stringOffsets[base + 3],
      moduleInfo: moduleStructSize === SIZEOF_MODULE_NEW ? stringOffsets[base + 4] : { offset: 0, length: 0 },
      bytecodeOriginPath: moduleStructSize === SIZEOF_MODULE_NEW ? stringOffsets[base + 5] : { offset: 0, length: 0 },
      encoding: meta.encoding, loader: meta.loader, moduleFormat: meta.moduleFormat, side: meta.side,
    };

    const modOffset = modulesListOffset + i * moduleStructSize;
    let pos = modOffset;
    newBuf.writeUInt32LE(modStruct.name.offset, pos); newBuf.writeUInt32LE(modStruct.name.length, pos + 4); pos += 8;
    newBuf.writeUInt32LE(modStruct.contents.offset, pos); newBuf.writeUInt32LE(modStruct.contents.length, pos + 4); pos += 8;
    newBuf.writeUInt32LE(modStruct.sourcemap.offset, pos); newBuf.writeUInt32LE(modStruct.sourcemap.length, pos + 4); pos += 8;
    newBuf.writeUInt32LE(modStruct.bytecode.offset, pos); newBuf.writeUInt32LE(modStruct.bytecode.length, pos + 4); pos += 8;
    if (moduleStructSize === SIZEOF_MODULE_NEW) {
      newBuf.writeUInt32LE(modStruct.moduleInfo.offset, pos); newBuf.writeUInt32LE(modStruct.moduleInfo.length, pos + 4); pos += 8;
      newBuf.writeUInt32LE(modStruct.bytecodeOriginPath.offset, pos); newBuf.writeUInt32LE(modStruct.bytecodeOriginPath.length, pos + 4); pos += 8;
    }
    newBuf.writeUInt8(modStruct.encoding, pos); newBuf.writeUInt8(modStruct.loader, pos + 1);
    newBuf.writeUInt8(modStruct.moduleFormat, pos + 2); newBuf.writeUInt8(modStruct.side, pos + 3);
  }

  // 写入 Offsets
  let op = offsetsOffset;
  newBuf.writeBigUInt64LE(BigInt(offsetsOffset), op); op += 8;
  newBuf.writeUInt32LE(modulesListOffset, op); newBuf.writeUInt32LE(modulesListSize, op + 4); op += 8;
  newBuf.writeUInt32LE(bunOffsets.entryPointId, op); op += 4;
  newBuf.writeUInt32LE(compileExecArgvOffset, op); newBuf.writeUInt32LE(compileExecArgvLength, op + 4); op += 8;
  newBuf.writeUInt32LE(bunOffsets.flags, op);

  // 写入 trailer
  BUN_TRAILER.copy(newBuf, trailerOffset);

  return newBuf;
}

function buildSectionData(bunBuffer, headerSize) {
  const sectionData = Buffer.allocUnsafe(headerSize + bunBuffer.length);
  if (headerSize === 8) {
    sectionData.writeBigUInt64LE(BigInt(bunBuffer.length), 0);
  } else {
    sectionData.writeUInt32LE(bunBuffer.length, 0);
  }
  bunBuffer.copy(sectionData, headerSize);
  return sectionData;
}

function atomicWriteBinary(LIEF, binary, outputPath, originalPath) {
  const tempPath = outputPath + ".tmp";
  binary.write(tempPath);
  try {
    const origStat = fs.statSync(originalPath);
    fs.chmodSync(tempPath, origStat.mode);
  } catch {}
  try {
    fs.renameSync(tempPath, outputPath);
  } catch (error) {
    try { if (fs.existsSync(tempPath)) fs.unlinkSync(tempPath); } catch {}
    if (error && (error.code === "ETXTBSY" || error.code === "EBUSY" || error.code === "EPERM")) {
      throw new Error("Cannot update the Claude executable while it is running. Please close all Claude instances and try again.");
    }
    throw error;
  }
}

function runCodesign(args, action) {
  try {
    execFileSync("codesign", args, { stdio: ["ignore", "pipe", "pipe"] });
  } catch (error) {
    const stderr = Buffer.isBuffer(error.stderr) ? error.stderr.toString("utf8").trim() : "";
    const detail = stderr ? `: ${stderr}` : "";
    throw new Error(`codesign ${action} failed${detail}`);
  }
}

function signAndVerifyMachO(outputPath) {
  runCodesign(["-s", "-", "-f", outputPath], "sign");
  runCodesign(["--verify", "--strict", "--verbose=4", outputPath], "verify");
}

function verifyPERepack(LIEF, outputPath, expectedBunBuffer) {
  const { bunData } = extractNativeBun(LIEF, outputPath);
  if (!bunData.equals(expectedBunBuffer)) {
    throw new Error("PE repack verification failed: embedded Bun data did not round-trip");
  }
}

function repackMachO(LIEF, machoBinary, binPath, newBunBuffer, outputPath, sectionHeaderSize) {
  // 移除旧签名
  if (machoBinary.hasCodeSignature) {
    machoBinary.removeSignature();
  }

  const bunSegment = machoBinary.getSegment("__BUN");
  if (!bunSegment) throw new Error("__BUN segment not found");
  const bunSection = bunSegment.getSection("__bun");
  if (!bunSection) throw new Error("__bun section not found");

  const newSectionData = buildSectionData(newBunBuffer, sectionHeaderSize);
  const sizeDiff = newSectionData.length - Number(bunSection.size);

  if (sizeDiff > 0) {
    const isARM64 = machoBinary.header.cpuType === LIEF.MachO.Header.CPU_TYPE.ARM64;
    const PAGE_SIZE = isARM64 ? 16384 : 4096;
    const alignedSizeDiff = Math.ceil(sizeDiff / PAGE_SIZE) * PAGE_SIZE;
    const success = machoBinary.extendSegment(bunSegment, alignedSizeDiff);
    if (!success) throw new Error("Failed to extend __BUN segment");
  }

  bunSection.content = newSectionData;
  bunSection.size = BigInt(newSectionData.length);

  atomicWriteBinary(LIEF, machoBinary, outputPath, binPath);

  // macOS 必须重签并通过校验；否则运行时会被系统直接 kill。
  signAndVerifyMachO(outputPath);
}

function repackPE(LIEF, peBinary, binPath, newBunBuffer, outputPath, sectionHeaderSize, section) {
  const newSectionData = buildSectionData(newBunBuffer, sectionHeaderSize);
  section.content = newSectionData;
  section.size = BigInt(newSectionData.length);
  if ("virtualSize" in section) {
    section.virtualSize = BigInt(newSectionData.length);
  }

  atomicWriteBinary(LIEF, peBinary, outputPath, binPath);
  verifyPERepack(LIEF, outputPath, newBunBuffer);
}

// ============================================================================
// ELF (Linux) 提取/重打包 — 纯 JS 节手术，不依赖 node-lief
//
// Bun 在 Linux 上把 standalone 数据放进正规 ELF 节 `.bun`（PT_LOAD 段内），
// 节内容 = [u32/u64 大小头][Bun data blob]，blob 内偏移全部相对 blob 起点。
// 重打包 = 替换 `.bun` 节内容，并把节后内容（.symtab / .strtab / 节头表等）
// 按 65536 对齐的整数倍整体平移，同步修正 ELF 头 / 节头表 / 程序头表偏移。
// 65536 覆盖 x64 (4K)、arm64 (4K/16K/64K) 的所有页大小，平移不破坏任何对齐。
// ============================================================================

function parseElfLayout(fd) {
  const ehdr = Buffer.alloc(64);
  fs.readSync(fd, ehdr, 0, 64, 0);
  if (!(ehdr[0] === 0x7f && ehdr[1] === 0x45 && ehdr[2] === 0x4c && ehdr[3] === 0x46)) {
    throw new Error("Not an ELF binary");
  }
  if (ehdr[4] !== 2 || ehdr[5] !== 1) {
    throw new Error("Only ELF64 little-endian binaries are supported");
  }
  const layout = {
    ehdr,
    e_phoff: Number(ehdr.readBigUInt64LE(0x20)),
    e_shoff: Number(ehdr.readBigUInt64LE(0x28)),
    e_phentsize: ehdr.readUInt16LE(0x36),
    e_phnum: ehdr.readUInt16LE(0x38),
    e_shentsize: ehdr.readUInt16LE(0x3a),
    e_shnum: ehdr.readUInt16LE(0x3c),
    e_shstrndx: ehdr.readUInt16LE(0x3e),
  };
  if (!layout.e_shoff || !layout.e_shnum) {
    throw new Error("ELF has no section headers");
  }
  layout.shdrs = Buffer.alloc(layout.e_shentsize * layout.e_shnum);
  fs.readSync(fd, layout.shdrs, 0, layout.shdrs.length, layout.e_shoff);
  layout.phdrs = Buffer.alloc(layout.e_phentsize * layout.e_phnum);
  fs.readSync(fd, layout.phdrs, 0, layout.phdrs.length, layout.e_phoff);

  const shstr = readElfShdr(layout, layout.e_shstrndx);
  const shstrtab = Buffer.alloc(shstr.size);
  fs.readSync(fd, shstrtab, 0, shstr.size, shstr.offset);
  layout.sectionName = (nameOff) => {
    const end = shstrtab.indexOf(0, nameOff);
    return shstrtab.subarray(nameOff, end === -1 ? shstrtab.length : end).toString("utf8");
  };
  return layout;
}

function readElfShdr(layout, index) {
  const base = index * layout.e_shentsize;
  const view = layout.shdrs.subarray(base, base + layout.e_shentsize);
  return {
    index,
    nameOff: view.readUInt32LE(0),
    type: view.readUInt32LE(4),
    offset: Number(view.readBigUInt64LE(24)),
    size: Number(view.readBigUInt64LE(32)),
    addralign: Number(view.readBigUInt64LE(48)),
  };
}

const ELF_SHT_PROGBITS = 1;

function extractFromELFFile(binaryPath) {
  const fd = fs.openSync(binaryPath, "r");
  try {
    const layout = parseElfLayout(fd);

    // 优先按节名 `.bun`；名字变了再退化为逐节尝试解析（与 PE 扫描策略一致）
    let section = null;
    for (let i = 0; i < layout.e_shnum; i++) {
      const candidate = readElfShdr(layout, i);
      if (candidate.type === ELF_SHT_PROGBITS && layout.sectionName(candidate.nameOff) === ".bun") {
        section = candidate;
        break;
      }
    }

    let parsed = null;
    if (section) {
      const content = Buffer.alloc(section.size);
      fs.readSync(fd, content, 0, section.size, section.offset);
      parsed = extractBunDataFromSection(content);
    } else {
      for (let i = 0; i < layout.e_shnum; i++) {
        const candidate = readElfShdr(layout, i);
        if (candidate.type !== ELF_SHT_PROGBITS || candidate.size < SIZEOF_OFFSETS + BUN_TRAILER.length) continue;
        try {
          const content = Buffer.alloc(candidate.size);
          fs.readSync(fd, content, 0, candidate.size, candidate.offset);
          parsed = extractBunDataFromSection(content);
          section = candidate;
          break;
        } catch {}
      }
    }

    if (!section || !parsed) {
      throw new Error("Bun section not found in ELF binary");
    }
    return { ...parsed, format: "ELF", section, layout };
  } finally {
    fs.closeSync(fd);
  }
}

function copyFileRange(srcFd, dstFd, srcStart, srcEnd, dstStart) {
  const chunk = Buffer.alloc(8 * 1024 * 1024);
  let src = srcStart;
  let dst = dstStart;
  while (src < srcEnd) {
    const want = Math.min(chunk.length, srcEnd - src);
    const got = fs.readSync(srcFd, chunk, 0, want, src);
    if (got <= 0) throw new Error("ELF repack: unexpected EOF while copying");
    fs.writeSync(dstFd, chunk, 0, got, dst);
    src += got;
    dst += got;
  }
}

function repackELFFile(binaryPath, newBunBuffer, sectionHeaderSize, section, layout) {
  const newSectionData = buildSectionData(newBunBuffer, sectionHeaderSize);
  const secOff = section.offset;
  const oldSize = section.size;
  // 平移量取 65536 的整数倍：节后所有内容的对齐（含未来页大小变化）都不被破坏
  const padAlign = Math.max(65536, section.addralign || 1);
  const pad = (((oldSize - newSectionData.length) % padAlign) + padAlign) % padAlign;
  const delta = newSectionData.length + pad - oldSize;

  const stat = fs.statSync(binaryPath);
  const tmpPath = binaryPath + ".tmp";
  const srcFd = fs.openSync(binaryPath, "r");
  let dstFd = -1;
  try {
    dstFd = fs.openSync(tmpPath, "w", stat.mode);

    // 1) 节前内容原样复制；2) 写入新节内容 + 对齐填充；3) 节后内容整体平移复制
    copyFileRange(srcFd, dstFd, 0, secOff, 0);
    fs.writeSync(dstFd, newSectionData, 0, newSectionData.length, secOff);
    if (pad > 0) {
      fs.writeSync(dstFd, Buffer.alloc(pad), 0, pad, secOff + newSectionData.length);
    }
    copyFileRange(srcFd, dstFd, secOff + oldSize, stat.size, secOff + newSectionData.length + pad);

    // 4) 修正 ELF 头（e_phoff / e_shoff）
    const newPhoff = layout.e_phoff > secOff ? layout.e_phoff + delta : layout.e_phoff;
    const newShoff = layout.e_shoff > secOff ? layout.e_shoff + delta : layout.e_shoff;
    const ehdr = Buffer.from(layout.ehdr);
    ehdr.writeBigUInt64LE(BigInt(newPhoff), 0x20);
    ehdr.writeBigUInt64LE(BigInt(newShoff), 0x28);
    fs.writeSync(dstFd, ehdr, 0, ehdr.length, 0);

    // 5) 修正节头表：`.bun` 更新 sh_size；节后的节整体平移 sh_offset
    const shdrs = Buffer.from(layout.shdrs);
    for (let i = 0; i < layout.e_shnum; i++) {
      const base = i * layout.e_shentsize;
      const shOffset = Number(shdrs.readBigUInt64LE(base + 24));
      if (i === section.index) {
        shdrs.writeBigUInt64LE(BigInt(newSectionData.length), base + 32);
      } else if (shOffset > secOff) {
        shdrs.writeBigUInt64LE(BigInt(shOffset + delta), base + 24);
      }
    }
    fs.writeSync(dstFd, shdrs, 0, shdrs.length, newShoff);

    // 6) 修正程序头表：覆盖 `.bun` 的段扩缩 filesz/memsz；节后的段平移 p_offset
    const phdrs = Buffer.from(layout.phdrs);
    for (let i = 0; i < layout.e_phnum; i++) {
      const base = i * layout.e_phentsize;
      const pOffset = Number(phdrs.readBigUInt64LE(base + 8));
      const pFilesz = Number(phdrs.readBigUInt64LE(base + 32));
      const pMemsz = Number(phdrs.readBigUInt64LE(base + 40));
      if (pOffset > secOff) {
        phdrs.writeBigUInt64LE(BigInt(pOffset + delta), base + 8);
      } else if (pOffset + pFilesz >= secOff + oldSize) {
        phdrs.writeBigUInt64LE(BigInt(pFilesz + delta), base + 32);
        phdrs.writeBigUInt64LE(BigInt(pMemsz + delta), base + 40);
      }
    }
    fs.writeSync(dstFd, phdrs, 0, phdrs.length, newPhoff);
  } finally {
    fs.closeSync(srcFd);
    if (dstFd !== -1) fs.closeSync(dstFd);
  }

  try {
    fs.chmodSync(tmpPath, stat.mode);
  } catch {}
  try {
    fs.renameSync(tmpPath, binaryPath);
  } catch (error) {
    try { if (fs.existsSync(tmpPath)) fs.unlinkSync(tmpPath); } catch {}
    if (error && (error.code === "ETXTBSY" || error.code === "EBUSY" || error.code === "EPERM")) {
      throw new Error("Cannot update the Claude executable while it is running. Please close all Claude instances and try again.");
    }
    throw error;
  }

  // 7) 往返校验：重新提取，blob 必须与写入内容完全一致
  const check = extractFromELFFile(binaryPath);
  if (!check.bunData.equals(newBunBuffer)) {
    throw new Error("ELF repack verification failed: embedded Bun data did not round-trip");
  }
}

// ============================================================================
// CLI 子命令实现
// ============================================================================

function cmdDetect() {
  const claudeCmd = process.argv[3];
  if (!claudeCmd) { process.stdout.write("unknown"); return; }
  const result = detectInstallation(claudeCmd);
  process.stdout.write(result);
}

function cmdExtract() {
  const binaryPath = process.argv[3];
  const outputPath = process.argv[4];
  if (!binaryPath || !outputPath) {
    process.stderr.write("Usage: bun-binary-io.js extract <binary> <output>\n");
    process.exit(1);
  }

  let extracted;
  if (detectBinaryFormat(binaryPath) === "ELF") {
    // Linux ELF：纯 JS 提取，不需要 node-lief
    extracted = extractFromELFFile(binaryPath);
  } else {
    const LIEF = loadNodeLief();
    if (!LIEF) {
      process.stderr.write("Error: node-lief not found. Install with: npm install -g node-lief\n");
      process.exit(1);
    }
    extracted = extractNativeBun(LIEF, binaryPath);
  }

  const { bunData, bunOffsets, moduleStructSize } = extracted;
  const found = findClaudeModule(bunData, bunOffsets, moduleStructSize);
  if (!found || found.contents.length === 0) {
    process.stderr.write("Error: claude module not found in binary\n");
    process.exit(1);
  }

  fs.writeFileSync(outputPath, found.contents);
  process.stdout.write("ok");
}

function cmdRepack() {
  const binaryPath = process.argv[3];
  const jsPath = process.argv[4];
  if (!binaryPath || !jsPath) {
    process.stderr.write("Usage: bun-binary-io.js repack <binary> <js-file>\n");
    process.exit(1);
  }

  const modifiedJs = fs.readFileSync(jsPath);

  if (detectBinaryFormat(binaryPath) === "ELF") {
    // Linux ELF：纯 JS 节手术，不需要 node-lief
    const { bunData, bunOffsets, sectionHeaderSize, moduleStructSize, section, layout } = extractFromELFFile(binaryPath);
    const newBuffer = rebuildBunData(bunData, bunOffsets, modifiedJs, moduleStructSize);
    repackELFFile(binaryPath, newBuffer, sectionHeaderSize, section, layout);
    process.stdout.write("ok");
    return;
  }

  const LIEF = loadNodeLief();
  if (!LIEF) {
    process.stderr.write("Error: node-lief not found. Install with: npm install -g node-lief\n");
    process.exit(1);
  }

  LIEF.logging.disable();
  const { format, binary, section, segment, bunOffsets, bunData, sectionHeaderSize, moduleStructSize } = extractNativeBun(LIEF, binaryPath);
  const newBuffer = rebuildBunData(bunData, bunOffsets, modifiedJs, moduleStructSize);

  switch (format) {
    case "MachO":
      repackMachO(LIEF, binary, binaryPath, newBuffer, binaryPath, sectionHeaderSize, segment);
      break;
    case "PE":
      repackPE(LIEF, binary, binaryPath, newBuffer, binaryPath, sectionHeaderSize, section);
      break;
    default:
      process.stderr.write(`Error: unsupported native binary format ${format || "unknown"}\n`);
      process.exit(1);
  }
  process.stdout.write("ok");
}

function isClaudePackageName(name) {
  return name === "@anthropic-ai/claude-code" ||
    name === "@anthropic-ai/claude-code-darwin-arm64" ||
    name === "@anthropic-ai/claude-code-win32-x64" ||
    name === "@anthropic-ai/claude-code-linux-x64" ||
    name === "@anthropic-ai/claude-code-linux-arm64" ||
    name === "@anthropic-ai/claude-code-linux-x64-musl" ||
    name === "@anthropic-ai/claude-code-linux-arm64-musl";
}

function normalizeSemver(value) {
  const match = String(value || "").match(/\b\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?\b/);
  return match ? match[0] : "";
}

function readPackageVersionNearBinary(binaryPath) {
  let dir;
  try {
    dir = path.dirname(fs.realpathSync(binaryPath));
  } catch {
    dir = path.dirname(path.resolve(binaryPath));
  }

  for (let depth = 0; depth < 6; depth++) {
    const packageJson = path.join(dir, "package.json");
    try {
      const pkg = JSON.parse(fs.readFileSync(packageJson, "utf8"));
      const version = normalizeSemver(pkg.version);
      if (version && isClaudePackageName(pkg.name)) return version;
    } catch {}

    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }

  return "";
}

function readExecutableVersion(binaryPath) {
  let tempHome = "";
  try {
    tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "cczh-version-home-"));
    const output = execFileSync(binaryPath, ["--version"], {
      encoding: "utf8",
      timeout: 10000,
      stdio: ["ignore", "pipe", "pipe"],
      env: {
        ...process.env,
        HOME: tempHome,
        USERPROFILE: tempHome,
        XDG_CONFIG_HOME: path.join(tempHome, ".config"),
        XDG_CACHE_HOME: path.join(tempHome, ".cache"),
        XDG_DATA_HOME: path.join(tempHome, ".local", "share"),
      },
    });
    return normalizeSemver(output);
  } catch {
    return "";
  } finally {
    if (tempHome) {
      try { fs.rmSync(tempHome, { recursive: true, force: true }); } catch {}
    }
  }
}

function cmdVersion() {
  const binaryPath = process.argv[3];
  if (!binaryPath) {
    process.stderr.write("Usage: bun-binary-io.js version <binary>\n");
    process.exit(1);
  }

  try {
    let extracted = null;
    if (detectBinaryFormat(binaryPath) === "ELF") {
      extracted = extractFromELFFile(binaryPath);
    } else {
      const LIEF = loadNodeLief();
      if (LIEF) {
        extracted = extractNativeBun(LIEF, binaryPath);
      }
    }
    if (extracted) {
      const found = findClaudeModule(extracted.bunData, extracted.bunOffsets, extracted.moduleStructSize);
      if (found && found.contents.length > 0) {
        // 从 JS 内容头部提取版本号（匹配 "// Version: X.Y.Z" 格式）。
        // 2.1.207 起头部先有 @bun pragma 和条款注释，版本行更靠后，窗口取 4096。
        const header = found.contents.subarray(0, 4096).toString("utf-8");
        const match = header.match(/\/\/ Version: (\S+)/);
        if (match) {
          process.stdout.write(match[1]);
          return;
        }
      }
    }
  } catch {
    // 继续走下面的安装包/可执行文件回退识别。
  }

  process.stdout.write(readPackageVersionNearBinary(binaryPath) || readExecutableVersion(binaryPath) || "");
}

function cmdResolve() {
  const inputPath = process.argv[3];
  if (!inputPath) {
    process.stderr.write("Usage: bun-binary-io.js resolve <path>\n");
    process.exit(1);
  }
  try {
    process.stdout.write(fs.realpathSync(inputPath));
  } catch {
    process.stdout.write(inputPath);
  }
}

function cmdCheckDeps() {
  // 可选参数：目标二进制路径。ELF 走纯 JS 通路，不需要 node-lief。
  const binaryPath = process.argv[3];
  if (binaryPath && detectBinaryFormat(binaryPath) === "ELF") {
    process.stdout.write("ok");
    return;
  }
  const LIEF = loadNodeLief();
  process.stdout.write(LIEF ? "ok" : "missing");
}

function cmdHash() {
  const binaryPath = process.argv[3];
  if (!binaryPath) {
    process.stderr.write("Usage: bun-binary-io.js hash <binary>\n");
    process.exit(1);
  }

  const hash = crypto.createHash("sha256");
  const fd = fs.openSync(binaryPath, "r");
  const buffer = Buffer.alloc(1024 * 1024);
  try {
    let bytesRead = 0;
    do {
      bytesRead = fs.readSync(fd, buffer, 0, buffer.length, null);
      if (bytesRead > 0) {
        hash.update(buffer.subarray(0, bytesRead));
      }
    } while (bytesRead > 0);
  } finally {
    fs.closeSync(fd);
  }

  process.stdout.write(hash.digest("hex"));
}

// ============================================================================
// CLI 入口
// ============================================================================

const command = process.argv[2];
switch (command) {
  case "detect": cmdDetect(); break;
  case "extract": cmdExtract(); break;
  case "repack": cmdRepack(); break;
  case "version": cmdVersion(); break;
  case "resolve": cmdResolve(); break;
  case "check-deps": cmdCheckDeps(); break;
  case "hash": cmdHash(); break;
  default:
    process.stderr.write(
      "Usage: bun-binary-io.js <command> [args...]\n" +
      "Commands: detect, extract, repack, version, resolve, check-deps, hash\n"
    );
    process.exit(1);
}
