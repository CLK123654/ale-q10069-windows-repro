import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { spawnSync } from "node:child_process";
import zlib from "node:zlib";

const repoRoot = path.resolve(import.meta.dirname, "..");
const artifactsRoot = path.join(repoRoot, "artifacts");
const evidenceRoot = path.join(repoRoot, "evidence");
assert.equal(process.platform, "win32", "该脚本只允许在原生Windows中运行");
assert.equal(process.env.GITHUB_ACTIONS, "true", "该脚本只允许由托管工作流运行");
assert.match(process.env.ImageOS ?? "", /^win25$/i, "托管镜像不是windows-2025");

const workRoot = fs.mkdtempSync(path.join(os.tmpdir(), "ale-q10069-"));

const attachmentNames = [
  "输入数据包.zip",
  "reference.zip",
  "关键标准答案.xlsx",
  "任务规格转化.xlsx",
];

const businessFiles = [
  "incoming/webhook_events.jsonl",
  "security/provider_keys.json",
  "routing/endpoint_policy.csv",
  "history/idempotency_ledger.csv",
  "history/attempt_history.csv",
  "rules/intake_contract.json",
  "rules/output_contract.json",
];

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function sha256File(file) {
  return sha256(fs.readFileSync(file));
}

function crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) {
      crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function readZip(zipFile) {
  const bytes = fs.readFileSync(zipFile);
  let eocd = -1;
  for (let offset = bytes.length - 22; offset >= Math.max(0, bytes.length - 65557); offset -= 1) {
    if (bytes.readUInt32LE(offset) === 0x06054b50) {
      eocd = offset;
      break;
    }
  }
  assert.notEqual(eocd, -1, `${path.basename(zipFile)}缺少ZIP目录`);
  const count = bytes.readUInt16LE(eocd + 10);
  let cursor = bytes.readUInt32LE(eocd + 16);
  const entries = new Map();
  for (let index = 0; index < count; index += 1) {
    assert.equal(bytes.readUInt32LE(cursor), 0x02014b50, "ZIP中央目录损坏");
    const flags = bytes.readUInt16LE(cursor + 8);
    const method = bytes.readUInt16LE(cursor + 10);
    const expectedCrc = bytes.readUInt32LE(cursor + 16);
    const compressedSize = bytes.readUInt32LE(cursor + 20);
    const uncompressedSize = bytes.readUInt32LE(cursor + 24);
    const nameLength = bytes.readUInt16LE(cursor + 28);
    const extraLength = bytes.readUInt16LE(cursor + 30);
    const commentLength = bytes.readUInt16LE(cursor + 32);
    const localOffset = bytes.readUInt32LE(cursor + 42);
    const nameBytes = bytes.subarray(cursor + 46, cursor + 46 + nameLength);
    const name = nameBytes.toString((flags & 0x800) !== 0 ? "utf8" : "utf8");
    assert.ok(name && !name.includes("\\"), `ZIP成员路径无效:${name}`);
    const normalized = path.posix.normalize(name);
    assert.ok(!normalized.startsWith("/") && !normalized.startsWith("../") && normalized !== "..", `ZIP成员越界:${name}`);
    assert.equal(bytes.readUInt32LE(localOffset), 0x04034b50, `ZIP本地头损坏:${name}`);
    const localNameLength = bytes.readUInt16LE(localOffset + 26);
    const localExtraLength = bytes.readUInt16LE(localOffset + 28);
    const dataStart = localOffset + 30 + localNameLength + localExtraLength;
    const compressed = bytes.subarray(dataStart, dataStart + compressedSize);
    let data;
    if (name.endsWith("/")) data = Buffer.alloc(0);
    else if (method === 0) data = Buffer.from(compressed);
    else if (method === 8) data = zlib.inflateRawSync(compressed);
    else throw new Error(`ZIP压缩方法不受支持:${method}`);
    assert.equal(data.length, uncompressedSize, `ZIP成员长度不符:${name}`);
    if (!name.endsWith("/")) assert.equal(crc32(data), expectedCrc, `ZIP成员CRC不符:${name}`);
    entries.set(normalized, { data, directory: name.endsWith("/") });
    cursor += 46 + nameLength + extraLength + commentLength;
  }
  return entries;
}

function extractZip(zipFile, targetRoot) {
  const entries = readZip(zipFile);
  fs.mkdirSync(targetRoot, { recursive: true });
  for (const [name, entry] of entries) {
    const target = path.resolve(targetRoot, ...name.split("/"));
    assert.ok(target === path.resolve(targetRoot) || target.startsWith(`${path.resolve(targetRoot)}${path.sep}`), `ZIP写出越界:${name}`);
    if (entry.directory) fs.mkdirSync(target, { recursive: true });
    else {
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.writeFileSync(target, entry.data);
    }
  }
  return [...entries.keys()].sort();
}

function xmlText(value) {
  return value
    .replaceAll("&lt;", "<")
    .replaceAll("&gt;", ">")
    .replaceAll("&quot;", '"')
    .replaceAll("&apos;", "'")
    .replaceAll("&amp;", "&");
}

function xmlAttribute(fragment, name) {
  const match = fragment.match(new RegExp(`(?:^|\\s)${name}="([^"]*)"`));
  return match ? xmlText(match[1]) : "";
}

function sharedStrings(entries) {
  const entry = entries.get("xl/sharedStrings.xml");
  if (!entry) return [];
  const xml = entry.data.toString("utf8");
  return [...xml.matchAll(/<(?:\w+:)?si\b[^>]*>([\s\S]*?)<\/(?:\w+:)?si>/g)].map((match) =>
    [...match[1].matchAll(/<(?:\w+:)?t\b[^>]*>([\s\S]*?)<\/(?:\w+:)?t>/g)]
      .map((item) => xmlText(item[1]))
      .join(""),
  );
}

function inspectWorkbook(file, expectedSheets) {
  const entries = readZip(file);
  const workbookXml = entries.get("xl/workbook.xml")?.data.toString("utf8") ?? "";
  const sheets = [...workbookXml.matchAll(/<(?:\w+:)?sheet\b([^>]*)\/?\s*>/g)].map((match) => ({
    name: xmlAttribute(match[1], "name"),
    state: xmlAttribute(match[1], "state") || "visible",
  }));
  assert.deepEqual(sheets.map((sheet) => sheet.name), expectedSheets, `${path.basename(file)}工作表顺序不符`);
  assert.ok(sheets.every((sheet) => sheet.state === "visible"), `${path.basename(file)}存在隐藏工作表`);
  return { entries, sheets };
}

function inspectSpecification(file) {
  const { entries, sheets } = inspectWorkbook(file, ["任务规格转化"]);
  const strings = sharedStrings(entries);
  const xml = entries.get("xl/worksheets/sheet1.xml")?.data.toString("utf8") ?? "";
  const values = new Map();
  for (const match of xml.matchAll(/<(?:\w+:)?c\b([^>]*)>([\s\S]*?)<\/(?:\w+:)?c>/g)) {
    const cell = xmlAttribute(match[1], "r");
    const type = xmlAttribute(match[1], "t");
    const raw = match[2].match(/<(?:\w+:)?v>([\s\S]*?)<\/(?:\w+:)?v>/)?.[1]
      ?? [...match[2].matchAll(/<(?:\w+:)?t\b[^>]*>([\s\S]*?)<\/(?:\w+:)?t>/g)].map((item) => item[1]).join("");
    const value = type === "s" ? strings[Number(raw)] : xmlText(raw ?? "");
    if (value !== "") values.set(cell, value);
  }
  assert.equal(values.get("A1"), "模块");
  assert.equal(values.get("B1"), "规格内容");
  assert.ok([...values.keys()].every((cell) => /^[AB]\d+$/.test(cell)), "任务规格使用了两列以外的单元格");
  assert.equal(values.get("A2"), "任务ID");
  assert.equal(values.get("B2"), "node_webhook_replay_queue_decision");
  assert.ok(!/10069|qid|record/i.test(values.get("B2")), "任务规格资产ID含线上标识");
  assert.equal(values.get("A17"), "不适合作为评分点的内容");
  assert.equal(values.size, 34, "任务规格应为17行两列");
  return { sheet_names: sheets.map((sheet) => sheet.name), populated_cells: values.size, task_asset_id: values.get("B2") };
}

function inspectArchiveSurface(entries, archiveName) {
  const files = [...entries.entries()].filter(([, entry]) => !entry.directory);
  const forbiddenNames = files
    .map(([name]) => name)
    .filter((name) => /(?:^|\/)(?:[^/]+\.(?:sh|bash|zsh|so|dylib|exe|dll)|Makefile)$/i.test(name));
  const binaryMatches = files
    .filter(([, entry]) => entry.data.length >= 4)
    .filter(([, entry]) => entry.data.subarray(0, 4).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46])))
    .map(([name]) => name);
  assert.deepEqual(forbiddenNames, [], `${archiveName}含平台专用文件`);
  assert.deepEqual(binaryMatches, [], `${archiveName}含ELF二进制`);
  return { file_count: files.length, forbidden_names: forbiddenNames, elf_members: binaryMatches };
}

function parseCsv(text) {
  const rows = [];
  let row = [];
  let cell = "";
  let quoted = false;
  for (let index = 0; index < text.length; index += 1) {
    const character = text[index];
    if (quoted) {
      if (character === '"' && text[index + 1] === '"') {
        cell += '"';
        index += 1;
      } else if (character === '"') quoted = false;
      else cell += character;
    } else if (character === '"') quoted = true;
    else if (character === ",") {
      row.push(cell);
      cell = "";
    } else if (character === "\n") {
      row.push(cell.replace(/\r$/, ""));
      rows.push(row);
      row = [];
      cell = "";
    } else cell += character;
  }
  assert.equal(quoted, false, "CSV引号未闭合");
  if (cell || row.length) {
    row.push(cell.replace(/\r$/, ""));
    rows.push(row);
  }
  const headers = rows.shift() ?? [];
  return rows
    .filter((values) => values.some((value) => value !== ""))
    .map((values) => Object.fromEntries(headers.map((header, index) => [header, values[index] ?? ""])));
}

function parseJsonLines(text) {
  return text.split(/\r?\n/).filter((line) => line.trim()).map((line) => JSON.parse(line));
}

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
  }
  return value;
}

function snapshotInputs(inputRoot) {
  const files = Object.fromEntries(businessFiles.map((relative) => {
    const file = path.join(inputRoot, ...relative.split("/"));
    assert.ok(fs.existsSync(file), `缺少业务输入:${relative}`);
    return [relative, sha256File(file)];
  }));
  return { files, digest: sha256(JSON.stringify(files)) };
}

function readDeliverables(root) {
  const decisions = parseCsv(fs.readFileSync(path.join(root, "deliverables", "intake_decisions.csv"), "utf8"));
  const queue = parseJsonLines(fs.readFileSync(path.join(root, "deliverables", "replay_queue.jsonl"), "utf8"));
  const handoff = parseCsv(fs.readFileSync(path.join(root, "deliverables", "endpoint_handoff.csv"), "utf8"));
  return { decisions, queue, handoff };
}

function semanticDigest(value) {
  return sha256(JSON.stringify(canonical(value)));
}

function prepareCase(label) {
  const root = path.join(workRoot, label);
  fs.mkdirSync(root, { recursive: true });
  const inputMembers = extractZip(path.join(artifactsRoot, "输入数据包.zip"), root);
  const referenceRoot = path.join(root, "reference");
  const referenceMembers = extractZip(path.join(artifactsRoot, "reference.zip"), referenceRoot);
  const inputRoot = path.join(root, "input_data");
  fs.copyFileSync(
    path.join(referenceRoot, "src", "rebuild_webhook_queue.mjs"),
    path.join(inputRoot, "src", "rebuild_webhook_queue.mjs"),
  );
  return { root, inputRoot, referenceRoot, inputMembers, referenceMembers };
}

function runProgram(inputRoot) {
  const result = spawnSync(
    "npm.cmd",
    ["run", "rebuild"],
    {
      cwd: inputRoot,
      encoding: "utf8",
      windowsHide: true,
      timeout: 60_000,
      env: { ...process.env, HTTP_PROXY: "", HTTPS_PROXY: "", ALL_PROXY: "", NO_PROXY: "*" },
    },
  );
  return {
    exit_code: result.status,
    signal: result.signal,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
    error: result.error?.message ?? "",
  };
}

function assertBusinessShape(deliverables) {
  assert.equal(deliverables.decisions.length, 13);
  assert.equal(new Set(deliverables.decisions.map((row) => row.event_id)).size, 13);
  assert.equal(deliverables.queue.length, 4);
  assert.deepEqual(deliverables.queue.map((row) => row.event_id), ["E001", "E011", "E009", "E013"]);
  assert.equal(deliverables.handoff.length, 3);
  assert.deepEqual(deliverables.handoff.map((row) => row.endpoint_id), ["billing-ledger", "media-publisher", "payout-ops"]);
  assert.equal(deliverables.decisions.find((row) => row.event_id === "E003")?.reason, "invalid_signature");
  assert.equal(deliverables.decisions.find((row) => row.event_id === "E004")?.reason, "unknown_provider");
}

function runStandard(label) {
  const prepared = prepareCase(label);
  const before = snapshotInputs(prepared.inputRoot);
  const execution = runProgram(prepared.inputRoot);
  assert.equal(execution.error, "", execution.error);
  assert.equal(execution.exit_code, 0, execution.stderr);
  const after = snapshotInputs(prepared.inputRoot);
  assert.deepEqual(after, before, `${label}修改了业务输入`);
  const actual = readDeliverables(prepared.inputRoot);
  const expected = readDeliverables(prepared.referenceRoot);
  assertBusinessShape(actual);
  assert.deepEqual(canonical(actual), canonical(expected), `${label}与Reference不一致`);
  assert.equal(
    sha256File(path.join(prepared.inputRoot, "src", "rebuild_webhook_queue.mjs")),
    sha256File(path.join(prepared.referenceRoot, "src", "rebuild_webhook_queue.mjs")),
  );
  return {
    directory_label: label,
    exit_code: execution.exit_code,
    input_digest_before: before.digest,
    input_digest_after: after.digest,
    semantic_digest: semanticDigest(actual),
    stdout_sha256: sha256(execution.stdout),
    stderr_sha256: sha256(execution.stderr),
    input_archive_member_count: prepared.inputMembers.filter((name) => !name.endsWith("/")).length,
    reference_archive_member_count: prepared.referenceMembers.filter((name) => !name.endsWith("/")).length,
  };
}

function runMutation(referenceDigest) {
  const prepared = prepareCase("规则变化 中文目录");
  const policyFile = path.join(prepared.inputRoot, "routing", "endpoint_policy.csv");
  const original = fs.readFileSync(policyFile, "utf8");
  const changed = original.replace(
    "video.ready,media-publisher,https://internal.invalid/media-publisher,true,4,180",
    "video.ready,media-publisher,https://internal.invalid/media-publisher,true,4,60",
  );
  assert.notEqual(changed, original, "规则变化没有命中输入");
  fs.writeFileSync(policyFile, changed);
  const before = snapshotInputs(prepared.inputRoot);
  const execution = runProgram(prepared.inputRoot);
  assert.equal(execution.exit_code, 0, execution.stderr);
  const after = snapshotInputs(prepared.inputRoot);
  assert.deepEqual(after, before, "规则变化运行修改了输入");
  const actual = readDeliverables(prepared.inputRoot);
  assertBusinessShape(actual);
  const queueEvent = actual.queue.find((row) => row.event_id === "E009");
  const decisionEvent = actual.decisions.find((row) => row.event_id === "E009");
  assert.equal(queueEvent?.scheduled_at_utc, "2026-07-30T09:12:00Z");
  assert.equal(decisionEvent?.scheduled_at_utc, "2026-07-30T09:12:00Z");
  const digest = semanticDigest(actual);
  assert.notEqual(digest, referenceDigest, "规则变化没有改变业务结果");
  return {
    changed_rule: "media-publisher的base_delay_seconds从180改为60",
    exit_code: execution.exit_code,
    input_digest_before: before.digest,
    input_digest_after: after.digest,
    changed_event_id: "E009",
    changed_scheduled_at_utc: queueEvent.scheduled_at_utc,
    semantic_digest: digest,
  };
}

function runCrlf(referenceDigest) {
  const prepared = prepareCase("CRLF兼容 中文目录");
  const converted = [];
  for (const relative of [
    "routing/endpoint_policy.csv",
    "history/idempotency_ledger.csv",
    "history/attempt_history.csv",
  ]) {
    const file = path.join(prepared.inputRoot, ...relative.split("/"));
    const original = fs.readFileSync(file, "utf8");
    const crlf = original.replace(/\r?\n/g, "\r\n");
    fs.writeFileSync(file, crlf);
    assert.ok(fs.readFileSync(file).includes(Buffer.from("\r\n")), `${relative}没有转换为CRLF`);
    converted.push(relative);
  }
  const before = snapshotInputs(prepared.inputRoot);
  const execution = runProgram(prepared.inputRoot);
  assert.equal(execution.exit_code, 0, execution.stderr);
  const after = snapshotInputs(prepared.inputRoot);
  assert.deepEqual(after, before, "CRLF运行修改了业务输入");
  const actual = readDeliverables(prepared.inputRoot);
  assertBusinessShape(actual);
  assert.equal(semanticDigest(actual), referenceDigest, "CRLF输入改变了业务语义");
  return {
    converted_files: converted,
    exit_code: execution.exit_code,
    input_digest_before: before.digest,
    input_digest_after: after.digest,
    semantic_digest: semanticDigest(actual),
  };
}

function runNegative() {
  const prepared = prepareCase("无效输入 中文目录");
  fs.rmSync(path.join(prepared.inputRoot, "security", "provider_keys.json"));
  assert.ok(!fs.existsSync(path.join(prepared.inputRoot, "deliverables")));
  const execution = runProgram(prepared.inputRoot);
  assert.notEqual(execution.exit_code, 0, "缺失公钥文件时错误返回0");
  assert.ok(!fs.existsSync(path.join(prepared.inputRoot, "deliverables")), "无效输入留下交付物");
  return {
    removed_input: "security/provider_keys.json",
    exit_code: execution.exit_code,
    deliverables_absent: true,
    stdout_sha256: sha256(execution.stdout),
    stderr_sha256: sha256(execution.stderr),
  };
}

function networkSurface() {
  const source = fs.readFileSync(path.join(workRoot, "第一次 干净目录", "reference", "src", "rebuild_webhook_queue.mjs"), "utf8");
  const forbidden = [
    /node:(?:http|https|net|tls|dgram|dns|child_process)/g,
    /\bfetch\s*\(/g,
    /\bWebSocket\b/g,
  ];
  const matches = forbidden.flatMap((pattern) => [...source.matchAll(pattern)].map((match) => match[0]));
  assert.deepEqual(matches, [], "Reference源码含外部网络调用面");
  assert.doesNotMatch(source, /\bE0(?:01|02|03|04|05|06|07|08|09|10|11|12|13)\b/u, "业务源码硬编码样例事件ID");
  return { external_network_api_matches: matches, hardcoded_sample_event_ids: [], formal_run_network_access: "none" };
}

fs.mkdirSync(evidenceRoot, { recursive: true });
try {
  for (const name of attachmentNames) assert.ok(fs.existsSync(path.join(artifactsRoot, name)), `缺少附件:${name}`);
  const attachments = Object.fromEntries(attachmentNames.map((name) => [name, sha256File(path.join(artifactsRoot, name))]));
  const inputArchiveSurface = inspectArchiveSurface(readZip(path.join(artifactsRoot, "输入数据包.zip")), "输入数据包.zip");
  const referenceArchiveSurface = inspectArchiveSurface(readZip(path.join(artifactsRoot, "reference.zip")), "reference.zip");
  const answerWorkbook = inspectWorkbook(path.join(artifactsRoot, "关键标准答案.xlsx"), [
    "交付物答案清单",
    "固定字段答案",
    "固定集合答案",
    "固定数值答案",
    "允许变体答案",
  ]);
  const specification = inspectSpecification(path.join(artifactsRoot, "任务规格转化.xlsx"));
  const first = runStandard("第一次 干净目录");
  const second = runStandard("第二次 中文路径");
  assert.equal(first.semantic_digest, second.semantic_digest, "两次干净运行的结构化语义不同");
  const crlf = runCrlf(first.semantic_digest);
  const mutation = runMutation(first.semantic_digest);
  const negative = runNegative();
  const network = networkSurface();
  const report = {
    schema_version: 1,
    task_asset_id: "node_webhook_replay_queue_decision",
    result: "PASS",
    generated_at_utc: new Date().toISOString(),
    git_commit_sha: process.env.GITHUB_SHA ?? "local",
    workflow_run_id: process.env.GITHUB_RUN_ID ?? "local",
    workflow_run_attempt: process.env.GITHUB_RUN_ATTEMPT ?? "local",
    runner: {
      os: process.env.RUNNER_OS ?? process.platform,
      arch: process.env.RUNNER_ARCH ?? process.arch,
      image_os: process.env.ImageOS ?? "local",
      image_version: process.env.ImageVersion ?? "local",
      node: process.version,
      powershell: process.env.QA_PWSH_VERSION ?? "unknown",
      powershell_hosted_workflow: process.env.GITHUB_ACTIONS === "true",
    },
    attachment_sha256: attachments,
    archive_surface: {
      input: inputArchiveSurface,
      standard_delivery: referenceArchiveSurface,
    },
    workbook_checks: {
      answer_sheet_names: answerWorkbook.sheets.map((sheet) => sheet.name),
      specification,
    },
    clean_runs: [first, second],
    crlf_run: crlf,
    positive_mutation: mutation,
    invalid_input: negative,
    network,
  };
  fs.writeFileSync(path.join(evidenceRoot, "windows-verification.json"), `${JSON.stringify(report, null, 2)}\n`);
  const audit = {
    schema_version: 1,
    result: "PASS",
    git_commit_sha: report.git_commit_sha,
    workflow_run_id: report.workflow_run_id,
    assertions: {
      native_windows_2025: report.runner.os === "Windows" && /^win25$/i.test(report.runner.image_os) && report.runner.powershell_hosted_workflow,
      powershell_recorded: report.runner.powershell !== "unknown",
      node_24: /^v24\./.test(report.runner.node),
      four_attachment_hashes_recorded: Object.keys(attachments).length === 4,
      archives_portable: inputArchiveSurface.forbidden_names.length === 0 && referenceArchiveSurface.forbidden_names.length === 0,
      independent_directories_equal: first.semantic_digest === second.semantic_digest,
      crlf_equal: crlf.semantic_digest === first.semantic_digest,
      inputs_unchanged: [first, second, crlf, mutation].every((item) => item.input_digest_before === item.input_digest_after),
      input_change_observed: mutation.semantic_digest !== first.semantic_digest,
      invalid_input_rejected: negative.exit_code !== 0 && negative.deliverables_absent,
      no_external_network_api: network.external_network_api_matches.length === 0,
    },
  };
  assert.ok(Object.values(audit.assertions).every(Boolean), "Windows审计断言未全部通过");
  fs.writeFileSync(path.join(evidenceRoot, "windows-audit.json"), `${JSON.stringify(audit, null, 2)}\n`);
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
} finally {
  fs.rmSync(workRoot, { recursive: true, force: true });
}
