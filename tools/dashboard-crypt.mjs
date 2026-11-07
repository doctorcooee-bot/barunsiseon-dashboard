#!/usr/bin/env node
// =============================================================
//  작업 현황판 암호화 도구
//
//  GitHub Pages 는 누구나 파일을 받을 수 있으므로, 현황 내용은 암호화한
//  status.enc.js 로만 올린다. 비밀번호를 아는 사람만 dashboard.html 에서 연다.
//
//  구조 (비밀번호 없이도 갱신할 수 있게 두 겹으로 잠금)
//   - dashboard-key.js : 공개 키 + 「비밀번호로 잠근」 비밀 키
//   - status.enc.js    : 현황 JSON 을 새 AES 키로 암호화, 그 AES 키는 공개 키로 잠금
//   → 갱신(encrypt)에는 비밀번호가 필요 없고, 여는 데만 비밀번호가 필요하다.
//
//  사용법 (Node 18 이상)
//   node tools/dashboard-crypt.mjs encrypt status.json     현황 JSON → status.enc.js
//   node tools/dashboard-crypt.mjs passwd                  비밀번호 바꾸기 (예전 비밀번호 필요)
//   node tools/dashboard-crypt.mjs decrypt [out.json]      status.enc.js 를 풀어 보기
//   node tools/dashboard-crypt.mjs init                    새 열쇠 만들기 (모든 기기의 「기억하기」가 풀림)
//
//  비밀번호는 화면에 안 보이게 묻는다. 자동화할 때만 환경변수 DASH_PASSWORD
//  (passwd 는 DASH_NEW_PASSWORD 도)를 쓴다. 비밀번호를 파일이나 커밋에 적지 않는다.
//
//  원본 현황 JSON(status.json)은 main 에 올리지 않는다 — 비공개 브랜치
//  `dashboard-data` 에만 둔다 (.gitignore 에도 넣어 둠).
// =============================================================
import { webcrypto as crypto } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import readline from "node:readline";
import { fileURLToPath } from "node:url";

const subtle = crypto.subtle;
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const KEY_FILE = path.join(ROOT, "dashboard-key.js");
const ENC_FILE = path.join(ROOT, "status.enc.js");
const ITER = 600000;

const b64 = (buf) => Buffer.from(buf instanceof ArrayBuffer ? new Uint8Array(buf) : buf).toString("base64");
const unb64 = (s) => new Uint8Array(Buffer.from(s, "base64"));
const enc = new TextEncoder();
const dec = new TextDecoder();

function readVar(file, name) {
  const txt = fs.readFileSync(file, "utf8");
  const i = txt.indexOf(`window.${name} =`);
  if (i < 0) throw new Error(`${path.basename(file)} 에 window.${name} 가 없습니다`);
  return JSON.parse(txt.slice(txt.indexOf("=", i) + 1).trim().replace(/;\s*$/, ""));
}
function writeVar(file, name, obj, comment) {
  fs.writeFileSync(file, `// ${comment}\nwindow.${name} = ${JSON.stringify(obj)};\n`);
}

function ask(question) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    const write = rl._writeToOutput.bind(rl);
    rl._writeToOutput = (s) => { if (s.includes(question)) write(s); else if (s.includes("\n")) write("\n"); };
    rl.question(question, (a) => { rl.close(); resolve(a); });
  });
}
async function password(envName, question, confirm = false) {
  if (process.env[envName]) return process.env[envName];
  const p = await ask(question);
  if (confirm) {
    const p2 = await ask("한 번 더 입력: ");
    if (p !== p2) throw new Error("두 번 입력한 비밀번호가 다릅니다");
  }
  if (!p) throw new Error("비밀번호가 비어 있습니다");
  if (p.length < 8) console.warn("주의: 8자보다 짧은 비밀번호는 몇 분 안에 다 시험해 볼 수 있습니다 (원장님 결정으로 허용)");
  return p;
}

async function passKey(pw, salt, iter) {
  const base = await subtle.importKey("raw", enc.encode(pw), "PBKDF2", false, ["deriveKey"]);
  return subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt, iterations: iter }, base,
    { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}
async function lockPrivate(pkcs8, pw) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const k = await passKey(pw, salt, ITER);
  const data = await subtle.encrypt({ name: "AES-GCM", iv }, k, pkcs8);
  return { kdf: "PBKDF2-SHA256", iter: ITER, salt: b64(salt), iv: b64(iv), data: b64(data) };
}
async function unlockPrivate(locked, pw) {
  const k = await passKey(pw, unb64(locked.salt), locked.iter);
  try {
    return await subtle.decrypt({ name: "AES-GCM", iv: unb64(locked.iv) }, k, unb64(locked.data));
  } catch {
    throw new Error("비밀번호가 맞지 않습니다");
  }
}

async function cmdInit() {
  if (fs.existsSync(KEY_FILE) && !process.argv.includes("--force")) {
    throw new Error("dashboard-key.js 가 이미 있습니다. 새 열쇠로 바꾸려면 --force 를 붙이세요 (그 뒤 encrypt 를 다시 해야 합니다)");
  }
  const pw = await password("DASH_PASSWORD", "새 비밀번호: ", true);
  const pair = await subtle.generateKey({ name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["encrypt", "decrypt"]);
  const spki = await subtle.exportKey("spki", pair.publicKey);
  const pkcs8 = await subtle.exportKey("pkcs8", pair.privateKey);
  writeVar(KEY_FILE, "DASH_KEY", { v: 1, publicKey: b64(spki), privateKey: await lockPrivate(pkcs8, pw) },
    "작업 현황판 열쇠 — 공개 키와, 비밀번호로 잠근 비밀 키. tools/dashboard-crypt.mjs 가 만든다.");
  console.log("dashboard-key.js 를 만들었습니다.");
}

async function cmdPasswd() {
  const key = readVar(KEY_FILE, "DASH_KEY");
  const oldPw = await password("DASH_PASSWORD", "지금 비밀번호: ");
  const pkcs8 = await unlockPrivate(key.privateKey, oldPw);
  const newPw = await password("DASH_NEW_PASSWORD", "새 비밀번호: ", true);
  key.privateKey = await lockPrivate(pkcs8, newPw);
  writeVar(KEY_FILE, "DASH_KEY", key, "작업 현황판 열쇠 — 공개 키와, 비밀번호로 잠근 비밀 키. tools/dashboard-crypt.mjs 가 만든다.");
  console.log("비밀번호를 바꿨습니다. dashboard-key.js 를 커밋 · 푸시하면 적용됩니다.");
}

// 화면(dashboard.html)이 기대하는 형식인지 확인 — 틀리면 암호화하지 않는다
function checkStatus(d) {
  const fail = (m) => { throw new Error("status.json 형식 오류: " + m); };
  const isArr = (k) => Array.isArray(d[k]) || fail(`${k} 는 목록이어야 합니다`);
  if (!d || typeof d !== "object") fail("JSON 객체가 아닙니다");
  if (isNaN(Date.parse(d.updatedAt))) fail("updatedAt 이 날짜가 아닙니다 (예: 2026-11-02T14:10:00+09:00)");
  const c = d.calendar || fail("calendar 가 없습니다");
  for (const k of ["start", "end", "mediaFrom"]) if (!/^\d{4}-\d{2}-\d{2}$/.test(c[k] || "")) fail(`calendar.${k} 는 YYYY-MM-DD`);
  if (!c.slots || !Object.keys(c.slots).length) fail("calendar.slots 가 비어 있습니다");
  if (!d.kpis || typeof d.kpis.mediaSets !== "number") fail("kpis.mediaSets 숫자가 없습니다");
  if (!d.columns || typeof d.columns !== "object") fail("columns 가 없습니다");
  ["decisions", "projects", "routines", "done", "sessions"].forEach(isArr);
  const ST = ["ok", "run", "wait", "stop", "idle"];
  d.projects.forEach((p, i) => {
    for (const k of ["name", "status", "label", "summary"]) if (!p[k]) fail(`projects[${i}].${k} 가 없습니다`);
    if (!ST.includes(p.status)) fail(`projects[${i}].status 는 ${ST.join("/")} 중 하나`);
    if (p.rows && !p.rows.every((r) => Array.isArray(r) && r.length === 2)) fail(`projects[${i}].rows 는 [이름, 내용] 목록`);
    if (p.meter && !(typeof p.meter.done === "number" && typeof p.meter.total === "number")) fail(`projects[${i}].meter 숫자 오류`);
  });
  const checkLinks = (links, where) => {
    if (links === undefined) return;
    if (!Array.isArray(links) || !links.every((l) => Array.isArray(l) && l.length === 2 && /^https:\/\//.test(l[1])))
      fail(`${where} 는 [이름, https 주소] 목록이어야 합니다`);
  };
  checkLinks(d.quicklinks, "quicklinks");
  // blog: { "MM-DD": [[제목, https 주소]] } — 칼럼 달력에서 그날 올라간 네이버 블로그 글
  if (d.blog !== undefined) {
    if (!d.blog || typeof d.blog !== "object" || Array.isArray(d.blog)) fail("blog 는 { \"MM-DD\": [[제목, https 주소]] }");
    for (const [k, v] of Object.entries(d.blog)) {
      if (!/^\d{2}-\d{2}$/.test(k)) fail(`blog 의 날짜 "${k}" 는 MM-DD`);
      checkLinks(v, `blog["${k}"]`);
    }
  }
  d.projects.forEach((p, i) => checkLinks(p.links, `projects[${i}].links`));
  d.decisions.forEach((x, i) => { if (!x.what || !["high", "mid", "low"].includes(x.prio)) fail(`decisions[${i}] 의 what/prio 오류`); });
  d.sessions.forEach((x, i) => { if (!x.id || !x.title || !ST.includes(x.status)) fail(`sessions[${i}] 의 id/title/status 오류`); });
  // url: 데스크톱 앱 로컬 세션처럼 claude.ai/code/<id> 로 안 열리는 대화의 주소 · pin: 자동 갱신 때 지우지 않는 줄
  d.sessions.forEach((x, i) => {
    if (x.url !== undefined && !/^(https:\/\/claude\.ai\/|claude:\/\/claude\.ai\/)/.test(x.url)) fail(`sessions[${i}].url 은 https://claude.ai/ 또는 claude://claude.ai/ 로 시작해야 합니다`);
    if (x.pin !== undefined && typeof x.pin !== "boolean") fail(`sessions[${i}].pin 은 true/false`);
  });
}

async function cmdEncrypt(src) {
  if (!src) throw new Error("암호화할 JSON 파일을 지정해 주세요 (예: status.json)");
  const json = fs.readFileSync(src, "utf8");
  checkStatus(JSON.parse(json)); // 화면이 깨지지 않게 형식 확인
  const key = readVar(KEY_FILE, "DASH_KEY");
  const pub = await subtle.importKey("spki", unb64(key.publicKey), { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]);
  const aes = await subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = await subtle.encrypt({ name: "AES-GCM", iv }, aes, enc.encode(json));
  const wrapped = await subtle.encrypt({ name: "RSA-OAEP" }, pub, await subtle.exportKey("raw", aes));
  writeVar(ENC_FILE, "STATUS_ENC", { v: 1, key: b64(wrapped), iv: b64(iv), data: b64(data) },
    "작업 현황판 내용 (암호화됨). tools/dashboard-crypt.mjs encrypt 로 만든다. 직접 고치지 않는다.");
  console.log(`status.enc.js 를 만들었습니다 (${json.length.toLocaleString()}자 → 암호화).`);
}

async function cmdDecrypt(out) {
  const key = readVar(KEY_FILE, "DASH_KEY");
  const box = readVar(ENC_FILE, "STATUS_ENC");
  const pw = await password("DASH_PASSWORD", "비밀번호: ");
  const pkcs8 = await unlockPrivate(key.privateKey, pw);
  const priv = await subtle.importKey("pkcs8", pkcs8, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["decrypt"]);
  const raw = await subtle.decrypt({ name: "RSA-OAEP" }, priv, unb64(box.key));
  const aes = await subtle.importKey("raw", raw, "AES-GCM", false, ["decrypt"]);
  const json = dec.decode(await subtle.decrypt({ name: "AES-GCM", iv: unb64(box.iv) }, aes, unb64(box.data)));
  if (out) { fs.writeFileSync(out, json); console.log(`${out} 에 풀어 저장했습니다.`); } else process.stdout.write(json);
}

const [cmd, arg] = process.argv.slice(2);
const run = { init: cmdInit, passwd: cmdPasswd, encrypt: () => cmdEncrypt(arg), decrypt: () => cmdDecrypt(arg) }[cmd];
if (!run) {
  console.log("사용법: node tools/dashboard-crypt.mjs <init|passwd|encrypt 파일|decrypt [파일]>");
  process.exit(1);
}
run().catch((e) => { console.error("오류: " + e.message); process.exit(1); });
