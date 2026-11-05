#!/usr/bin/env node

/**
 * STDK Chipset Porting - Validator, Manifest Generator & Port Verifier
 *
 * This script performs ONLY deterministic, non-intelligent work. It never
 * writes chipset-specific C code; the calling agent does that.
 *
 * Mode 1 - manifest (before writing code):
 *   node validate_and_scaffold.js --chipset <name> --firmware-link <url>
 *   1. Validates the chipset is not already ported.
 *   2. Validates a firmware/SDK link was provided.
 *   3. Prints a manifest: target dir, required files, and the exact STDK
 *      function signatures each file must implement, read from the repo's own
 *      src/include/bsp/*.h so they match the SDK version.
 *
 * Mode 2 - verify (after writing code):
 *   node validate_and_scaffold.js --chipset <name> --verify [--sdk-dir <path>] [--port-dir <path>]
 *   Static checks on the generated port. This is NOT a compile. It catches the
 *   mistakes that are cheap to detect by text analysis:
 *     - required files / signatures missing, or bodies left as TODO/stubs
 *     - STDK identifiers (IOT_*, iot_*) that don't exist in src/include
 *     - build wiring missing (Kconfig, component.cmake, include/bsp/<chip>/,
 *       CMakeLists.txt listing every file)
 *   and, when --sdk-dir points at the cloned vendor SDK:
 *     - #include "..." headers that exist nowhere in the SDK or STDK
 *     - functions/constants used that are defined nowhere in the SDK
 *     - vendor calls whose argument count differs from the SDK declaration
 *     - target_link_libraries names that don't exist in the vendor SDK
 *   plus, always: required signatures with wrong return/parameter types,
 *   Wi-Fi/BLE callbacks that are never invoked or only invoked from a handler
 *   nothing registers, and file names hashed into shared storage slots.
 *   The SDK checks need `grep` on the PATH. It cannot check that a vendor call's
 *   argument types (only their count) or semantics are right, nor that the code builds; do that by
 *   reading the SDK and compiling each file with the SDK's toolchain (see SKILL.md, Step 3).
 */

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const BSP_DIR = path.join(REPO_ROOT, 'src', 'port', 'bsp');
const INCLUDE_DIR = path.join(REPO_ROOT, 'src', 'include');

// The required BSP API is read from this repo's own headers (src/include/bsp/*.h),
// so it can never drift from the SDK version it ships with. Each declared function
// belongs to the source file of its category; this order is the manifest order.
const FILE_ROLES = [
  { role: 'system', owns: /^iot_bsp_(system_|get_bsp_)/ },
  { role: 'wifi', owns: /^iot_bsp_wifi_/ },
  { role: 'ble', owns: /^(iot_bsp_ble_|iot_send_indication$)/ },
  { role: 'fs', owns: /^iot_bsp_fs_/ },
  { role: 'nv_data', owns: /^iot_bsp_nv_/ },
  { role: 'random', owns: /^iot_bsp_random$/ },
  { role: 'debug', owns: /^iot_bsp_debug/ },
];
// Declared in the headers, but ports may omit them (see doc/porting_guide.md).
const OPTIONAL_APIS = new Set(['iot_bsp_fs_open_from_stnv', 'iot_bsp_system_set_timezone']);

// C keywords and common macros; never looked up as vendor symbols. libc names
// are resolved against /usr/include like any other symbol.
const IGNORED_CALLS = new Set([
  'if', 'else', 'for', 'while', 'do', 'switch', 'case', 'default', 'return', 'break', 'continue', 'goto',
  'sizeof', 'typedef', 'struct', 'union', 'enum', 'static', 'extern', 'const', 'volatile', 'inline',
  'void', 'char', 'short', 'int', 'long', 'float', 'double', 'signed', 'unsigned', 'defined',
  'NULL', 'true', 'false', 'bool', 'va_list', 'va_start', 'va_end', 'va_arg', 'EOF',
]);

function parseArgs(argv) {
  const params = {};
  for (let i = 0; i < argv.length; i++) {
    if (!argv[i].startsWith('--')) continue;
    const key = argv[i].slice(2);
    const next = argv[i + 1];
    if (next === undefined || next.startsWith('--')) {
      params[key] = true; // boolean flag
    } else {
      params[key] = next;
      i++;
    }
  }
  return params;
}

function fail(reason, message, extra = {}) {
  console.error(JSON.stringify({ status: 'error', reason, message, ...extra }, null, 2));
  process.exit(1);
}

function isLikelyUrl(value) {
  try {
    const url = new URL(value);
    return url.protocol === 'http:' || url.protocol === 'https:';
  } catch {
    return false;
  }
}

function sigName(sig) {
  // "iot_error_t iot_bsp_fs_open(const char *filename, ...)" -> "iot_bsp_fs_open"
  return /([A-Za-z_]\w*)\s*\(/.exec(sig)[1];
}

// Parses the BSP headers into { role: [signature, ...] }, plus any declared API
// that fits no category (a sign this script needs a new FILE_ROLES entry).
function loadBspApi() {
  const byRole = Object.fromEntries(FILE_ROLES.map(r => [r.role, []]));
  const unclassified = [];
  const dir = path.join(INCLUDE_DIR, 'bsp');
  for (const h of fs.readdirSync(dir).filter(f => f.endsWith('.h')).sort()) {
    const text = removePreprocessorLines(stripCommentsAndStrings(fs.readFileSync(path.join(dir, h), 'utf8')));
    for (const m of text.matchAll(/([A-Za-z_][\w\s*]*?)\b(iot_bsp_\w+|iot_send_indication)\s*\(([^;{}]*)\)\s*;/g)) {
      const [, rawType, name, rawArgs] = m;
      if (OPTIONAL_APIS.has(name)) continue;
      const type = rawType.trim().replace(/\s+/g, ' ');
      const args = rawArgs.trim().replace(/\s+/g, ' ') || 'void';
      const sig = `${type}${type.endsWith('*') ? '' : ' '}${name}(${args})`;
      const role = FILE_ROLES.find(r => r.owns.test(name));
      (role ? byRole[role.role] : unclassified).push(sig);
    }
  }
  return { byRole, unclassified };
}

function requiredFiles(chipset) {
  const { byRole } = loadBspApi();
  return FILE_ROLES.map(r => ({
    file: `iot_bsp_${r.role}_${chipset}.c`,
    required_signatures: byRole[r.role],
  }));
}

// A chipset counts as already ported when its bsp dir holds a full set of .c
// files. A half-generated port therefore doesn't block a re-run.
function supportedChipsets() {
  if (!fs.existsSync(BSP_DIR)) return [];
  const needed = FILE_ROLES.length;
  return fs.readdirSync(BSP_DIR, { withFileTypes: true })
    .filter(d => d.isDirectory())
    .filter(d => fs.readdirSync(path.join(BSP_DIR, d.name)).filter(f => f.endsWith('.c')).length >= needed)
    .map(d => d.name)
    .sort();
}

function walk(dir, predicate, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full, predicate, out);
    else if (predicate(entry.name)) out.push(full);
  }
  return out;
}

// Blank out comments and string/char literals, keeping every offset and
// newline intact so positions in the result map onto the original text.
function stripCommentsAndStrings(src) {
  const blank = s => s.replace(/[^\n]/g, ' ');
  return src
    .replace(/\/\*[\s\S]*?\*\//g, blank)
    .replace(/\/\/[^\n]*/g, blank)
    .replace(/"(?:\\.|[^"\\\n])*"/g, blank)
    .replace(/'(?:\\.|[^'\\\n])*'/g, blank);
}

function removePreprocessorLines(src) {
  return src.replace(/^[ \t]*#.*(?:\\\n.*)*$/gm, m => m.replace(/[^\n]/g, ' '));
}

// Returns the body text (between the outermost braces) of function `name`, or null.
function extractFunctionBody(raw, stripped, name) {
  const re = new RegExp(`(?:^|[^\\w.>])${name}\\s*\\([^;{}]*\\)\\s*\\{`, 'g');
  const m = re.exec(stripped);
  if (!m) return null;
  const open = stripped.indexOf('{', m.index + m[0].length - 1);
  let depth = 0;
  for (let i = open; i < stripped.length; i++) {
    if (stripped[i] === '{') depth++;
    else if (stripped[i] === '}' && --depth === 0) {
      return raw.slice(open + 1, i);
    }
  }
  return null;
}

// Identifiers the file defines itself (macros, functions, static data, types).
function localDefinitions(raw, stripped) {
  const defs = new Set();
  for (const m of raw.matchAll(/^[ \t]*#\s*define\s+(\w+)/gm)) defs.add(m[1]);
  for (const m of stripped.matchAll(/([A-Za-z_]\w*)\s*\([^;(){}]*\)\s*\{/g)) defs.add(m[1]);
  for (const m of stripped.matchAll(/\b(?:static|extern|typedef)\b[^;{()]*?\b(\w+)\s*(?:\[[^\]]*\])?\s*[=;,]/g)) defs.add(m[1]);
  for (const m of stripped.matchAll(/\b(?:enum|struct|union)\s+(\w+)/g)) defs.add(m[1]);
  for (const m of stripped.matchAll(/\}\s*(\w+)\s*;/g)) defs.add(m[1]);
  return defs;
}

function stdkHeaderWords() {
  const words = new Set();
  const basenames = new Set();
  for (const h of walk(INCLUDE_DIR, n => n.endsWith('.h'))) {
    basenames.add(path.basename(h));
    for (const w of fs.readFileSync(h, 'utf8').match(/\w+/g) || []) words.add(w);
  }
  return { words, basenames };
}

// Which of `words` occur (as whole words) anywhere under the given roots.
function grepKnownWords(words, roots) {
  const found = new Set();
  if (words.length === 0) return found;
  for (const root of roots.filter(r => fs.existsSync(r))) {
    let out = '';
    try {
      out = execFileSync('grep', ['-rhowF', '-f', '-', '--include=*.h', '--include=*.c', root],
        { input: words.join('\n') + '\n', encoding: 'utf8', maxBuffer: 1 << 28 });
    } catch (e) {
      out = e.stdout || ''; // grep exits 1 when nothing matches
    }
    for (const w of out.split('\n')) if (w) found.add(w);
  }
  return found;
}


// ---- prototype / arity helpers ------------------------------------------------

// Splits "a, f(b, c), d" on top-level commas.
function splitTopLevel(text) {
  const parts = [];
  let depth = 0, cur = '';
  for (const ch of text) {
    if ('([{'.includes(ch)) depth++;
    else if (')]}'.includes(ch)) depth--;
    if (ch === ',' && depth === 0) { parts.push(cur); cur = ''; } else cur += ch;
  }
  if (cur.trim() !== '' || parts.length) parts.push(cur);
  return parts.map(p => p.trim());
}

// Text between the parens that open at `openIdx`, or null if unbalanced.
function balancedParens(text, openIdx) {
  let depth = 0;
  for (let i = openIdx; i < text.length; i++) {
    if (text[i] === '(') depth++;
    else if (text[i] === ')' && --depth === 0) return text.slice(openIdx + 1, i);
  }
  return null;
}

// Reduces a parameter declaration to its type: drops the name and spacing, and
// turns "x[6]" into "*" so "uint8_t mac[6]" equals "uint8_t *mac".
function paramType(param) {
  let p = param.replace(/\[[^\]]*\]/g, '*').replace(/\s*\*\s*/g, ' * ').replace(/\s+/g, ' ').trim();
  if (p === '' || p === 'void') return 'void';
  const tokens = p.split(' ');
  const last = tokens[tokens.length - 1];
  const prev = tokens[tokens.length - 2];
  const keywords = /^(?:int|char|long|short|unsigned|signed|void|float|double|bool|const|volatile|\*)$/;
  if (tokens.length > 1 && !keywords.test(last) && !/^(?:struct|enum|union)$/.test(prev)) tokens.pop();
  // size_t is `unsigned int` on the 32-bit MCU toolchains STDK targets (esp32/bk7236 rely on it)
  return tokens.join(' ').replace(/ \*/g, '*').replace(/\*(?=\w)/g, '* ').replace(/\bsize_t\b/g, 'unsigned int').trim();
}

function normalizedPrototype(returnType, argText) {
  const ret = returnType.split(/[;{}]/).pop().replace(/\b(?:extern|static|inline)\b/g, '').replace(/\s*\*\s*/g, '*').replace(/\s+/g, ' ').trim();
  const params = splitTopLevel(argText).map(paramType);
  return `${ret}(${params.length ? params.join(',') : 'void'})`;
}

// True when the definition of `name` in `stripped` has the same return and
// parameter types as the required signature `sig`.
function prototypeMatches(stripped, name, sig) {
  const defRe = new RegExp(`([A-Za-z_][\\w\\s*]*?)\\b${name}\\s*\\(`, 'g');
  const sigM = /^([\s\S]*?)\b[A-Za-z_]\w*\s*\(([\s\S]*)\)\s*$/.exec(sig);
  const want = normalizedPrototype(sigM[1], sigM[2]);
  for (const m of stripped.matchAll(defRe)) {
    const open = m.index + m[0].length - 1;
    const args = balancedParens(stripped, open);
    if (args === null || !/^\s*\{/.test(stripped.slice(open + args.length + 2))) continue; // not a definition
    return normalizedPrototype(m[1], args) === want;
  }
  return true; // body found elsewhere by extractFunctionBody; don't guess
}

// For each name, the set of parameter counts the SDK headers declare for it.
// Names defined as macros, or declared variadic, are left out (cannot be checked).
function vendorParamCounts(names, sdkDir) {
  const out = Object.fromEntries(names.map(n => [n, new Set()]));
  const skip = new Set();
  for (const h of walk(sdkDir, n => n.endsWith('.h'))) {
    const raw = fs.readFileSync(h, 'utf8');
    const hit = names.filter(n => raw.includes(n));
    if (hit.length === 0) continue;
    const text = stripCommentsAndStrings(raw);
    for (const n of hit) {
      if (new RegExp(`#\\s*define\\s+${n}\\b`).test(text)) { skip.add(n); continue; }
      for (const m of text.matchAll(new RegExp(`(?:^|[^\\w.>])${n}\\s*\\(`, 'g'))) {
        const open = m.index + m[0].length - 1;
        const args = balancedParens(text, open);
        if (args === null || !/^\s*(?:;|__attribute__)/.test(text.slice(open + args.length + 2))) continue; // not a declaration
        if (/\.\.\./.test(args)) { skip.add(n); continue; }
        const parts = splitTopLevel(args);
        out[n].add(parts.length === 1 && (parts[0] === '' || parts[0] === 'void') ? 0 : parts.length);
      }
    }
  }
  for (const n of skip) delete out[n];
  return out;
}

// Name of the top-level function whose body contains offset `idx` of `code`, or null.
function enclosingFunction(code, idx) {
  for (const m of code.matchAll(/([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{/g)) {
    const open = m.index + m[0].length - 1;
    if (open > idx) break;
    let depth = 0;
    for (let i = open; i < code.length; i++) {
      if (code[i] === '{') depth++;
      else if (code[i] === '}' && --depth === 0) {
        if (idx < i) return m[1];
        break;
      }
    }
  }
  return null;
}

// True when `name` is used somewhere other than its own definition/prototype:
// passed or assigned as a function pointer, or called from elsewhere.
function isReferenced(code, name) {
  for (const m of code.matchAll(new RegExp(`\\b${name}\\b`, 'g'))) {
    const after = code.slice(m.index + name.length).match(/^\s*(.)/);
    if (!after || after[1] !== '(') return true; // `&name`, `= name;`, `name,` ...
    const before = code.slice(0, m.index).match(/(\S)\s*$/);
    if (before && !/[\w*]/.test(before[1])) return true; // a call, not `type name(`
    if (before && /^return$|^else$/.test((code.slice(0, m.index).match(/(\w+)\s*$/) || [])[1] || '')) return true;
  }
  return false;
}

// Checks that a stored callback is invoked (callRe) from a function that something
// else references, i.e. one that can actually run. Returns an error message or null.
function callbackProblem(code, callRe, what) {
  const calls = [...code.matchAll(callRe)];
  if (calls.length === 0) return `${what} is never invoked.`;
  const fns = new Set(calls.map(c => enclosingFunction(code, c.index)).filter(Boolean));
  if (fns.size && ![...fns].some(f => /^iot_/.test(f) || isReferenced(code, f))) {
    return `${what} is only invoked from ${[...fns].join(', ')}, which is never registered with or called by anything. Register it with the vendor stack.`;
  }
  return null;
}

function verify(chipset, params) {
  const portDir = path.resolve(typeof params['port-dir'] === 'string' ? params['port-dir'] : path.join(BSP_DIR, chipset));
  const sdkDir = typeof params['sdk-dir'] === 'string' ? path.resolve(params['sdk-dir']) : null;
  const issues = [];
  const add = (check, message, file) => issues.push({ check, file, message });
  const skipped = [];

  if (sdkDir && !fs.existsSync(sdkDir)) {
    fail('bad_sdk_dir', `--sdk-dir '${sdkDir}' does not exist.`);
  }
  if (!sdkDir) {
    skipped.push('vendor include/symbol checks (pass --sdk-dir <cloned vendor SDK> to enable)');
  }
  if (!fs.existsSync(portDir)) {
    fail('port_dir_missing', `Port directory '${portDir}' does not exist. Nothing to verify.`);
  }

  const stdk = stdkHeaderWords();
  const files = requiredFiles(chipset);
  const sources = {}; // file name -> { raw, stripped, code }

  // 1. required files, signatures and bodies
  let signaturesTotal = 0;
  let signaturesImplemented = 0;
  for (const { file, required_signatures } of files) {
    const full = path.join(portDir, file);
    signaturesTotal += required_signatures.length;
    if (!fs.existsSync(full)) {
      add('missing_file', `Required file ${file} does not exist.`, file);
      continue;
    }
    const raw = fs.readFileSync(full, 'utf8');
    const stripped = stripCommentsAndStrings(raw);
    sources[file] = { raw, stripped, code: removePreprocessorLines(stripped) };
    for (const sig of required_signatures) {
      const name = sigName(sig);
      const body = extractFunctionBody(raw, stripped, name);
      if (!body) {
        add('missing_signature', `${name}() is not defined. Required: ${sig}`, file);
      } else if (/TODO|FIXME|XXX|not\s+implemented|unimplemented|\bstub\b/i.test(body)) {
        add('stub_body', `${name}() contains a TODO/stub marker.`, file);
      } else if (!prototypeMatches(removePreprocessorLines(stripped), name, sig)) {
        add('signature_mismatch', `${name}() has a different return/parameter type than required: ${sig}`, file);
      } else {
        signaturesImplemented++;
      }
    }
  }
  const cmakeFile = path.join(portDir, 'CMakeLists.txt');
  if (!fs.existsSync(cmakeFile)) {
    add('missing_file', 'Required file CMakeLists.txt does not exist.', 'CMakeLists.txt');
  } else {
    const cmake = fs.readFileSync(cmakeFile, 'utf8');
    for (const { file } of files) {
      if (!cmake.includes(file)) add('cmake_missing_source', `CMakeLists.txt does not list ${file}.`, 'CMakeLists.txt');
    }
  }

  // 1b. behaviour checks that are cheap to detect in text
  const wifiSrc = sources[`iot_bsp_wifi_${chipset}.c`];
  if (wifiSrc) {
    if (!/\blast_disconnected_reason\b/.test(wifiSrc.code)) {
      add('status_field_unset', 'iot_bsp_wifi_get_status() never sets last_disconnected_reason; map the vendor disconnect reason (or IOT_WIFI_DISCONNECTED_REASON_UNKNOWN).', wifiSrc && `iot_bsp_wifi_${chipset}.c`);
    }
    if (/(?:->|\.)rssi\s*=\s*0\s*;/.test(wifiSrc.code)) {
      add('status_field_hardcoded', 'wifi_info->rssi is hard-coded to 0; read the real RSSI from the vendor SDK.', `iot_bsp_wifi_${chipset}.c`);
    }
    // the variable the registered callback is stored in, then where it is invoked
    const regBody = extractFunctionBody(wifiSrc.raw, wifiSrc.stripped, 'iot_bsp_wifi_register_event_cb') || '';
    const stored = (/\b([A-Za-z_]\w*)\s*=\s*(?!NULL\b)[A-Za-z_]\w*\s*;/.exec(regBody) || [])[1];
    if (stored) {
      const msg = callbackProblem(wifiSrc.code, new RegExp(`(?:\\(\\s*\\*\\s*${stored}\\s*\\)|\\b${stored})\\s*\\(`, 'g'), `the Wi-Fi event callback '${stored}'`);
      if (msg) add('callback_never_invoked', msg, `iot_bsp_wifi_${chipset}.c`);
    }
  }
  const bleSrc = sources[`iot_bsp_ble_${chipset}.c`];
  if (bleSrc) {
    for (const cb of ['write_cb', 'conn_cb']) {
      const msg = callbackProblem(bleSrc.code, new RegExp(`\\b${cb}\\s*\\)?\\s*\\(`, 'g'), `ble_cbs->${cb}`);
      if (msg) add('callback_never_invoked', `${msg} BLE writes/connection events would never reach STDK.`, `iot_bsp_ble_${chipset}.c`);
    }
  }
  const fsSrc = sources[`iot_bsp_fs_${chipset}.c`];
  if (fsSrc && /\bhash\b/i.test(fsSrc.code)) {
    add('fs_hashed_names', 'File names are hashed into storage slots; different NV keys can collide and overwrite each other. Give each iot_nvd_t key its own slot or use the vendor KV/file system.', `iot_bsp_fs_${chipset}.c`);
  }

  // 1c. every library named in target_link_libraries must exist in the vendor build
  if (fs.existsSync(cmakeFile) && sdkDir) {
    const cmakeText = fs.readFileSync(cmakeFile, 'utf8').replace(/#[^\n]*/g, '');
    const libs = new Set();
    for (const m of cmakeText.matchAll(/target_link_libraries\s*\(([^)]*)\)/g)) {
      for (const w of m[1].split(/\s+/)) {
        if (w && !/^(?:iotcore|PRIVATE|PUBLIC|INTERFACE)$/.test(w) && !w.startsWith('$')) libs.add(w);
      }
    }
    // Literal archives (`.a`/`.lib`/`.so`, possibly behind a ${VAR}/ prefix) must exist
    // somewhere under the SDK, matched by file name.
    const archives = [...libs].map(l => l.replace(/^["']|["']$/g, '')).filter(l => /\.(?:a|lib|so)$/.test(l));
    if (archives.length) {
      const present = new Set(walk(sdkDir, n => /\.(?:a|lib|so)$/.test(n)).map(f => path.basename(f)));
      for (const a of archives) {
        if (!present.has(path.basename(a))) {
          add('unknown_link_library', `target_link_libraries names '${a}', but no file with that name exists under the SDK. Take the real archive name from the vendor build output or library directory.`, 'CMakeLists.txt');
        }
      }
    }
    // Vendor build systems often create targets dynamically (esp-idf's idf::*), so
    // literal names can't be checked. What can be: a namespaced target `ns::name`
    // needs `ns::` to appear in some vendor build file, or it was made up.
    for (const ns of new Set([...libs].filter(l => l.includes('::')).map(l => l.split('::')[0] + '::'))) {
      let hit = '';
      try {
        hit = execFileSync('grep', ['-rlF', '-m1', '--include=CMakeLists.txt', '--include=*.cmake', '--include=Makefile*',
          '--include=*.mk', '--include=*.py', '--include=*.txt', ns, sdkDir], { encoding: 'utf8', maxBuffer: 1 << 26 });
      } catch (e) { hit = e.stdout || ''; }
      if (!hit.trim()) {
        const bad = [...libs].filter(l => l.startsWith(ns));
        add('unknown_link_library', `target_link_libraries names ${bad.join(', ')}, but '${ns}' appears in no vendor build file, so these targets do not exist. Take the real library/archive names from the vendor build system (or omit linking and say so in the summary).`, 'CMakeLists.txt');
      }
    }
  }

  // 2. build wiring outside the port directory
  const cfg = `STDK_IOT_CORE_BSP_SUPPORT_${chipset.toUpperCase().replace(/[^A-Z0-9]/g, '_')}`;
  const kconfig = path.join(REPO_ROOT, 'src', 'Kconfig');
  const component = path.join(REPO_ROOT, 'src', 'component.cmake');
  const custom = path.join(REPO_ROOT, 'src', 'include', 'bsp', chipset, 'iot_bsp_custom.h');
  if (!fs.existsSync(kconfig) || !new RegExp(`config\\s+${cfg}\\b`).test(fs.readFileSync(kconfig, 'utf8'))) {
    add('wiring_kconfig', `src/Kconfig has no 'config ${cfg}' entry in the STDK_IOT_CORE_BSP_SUPPORT choice.`);
  }
  if (!fs.existsSync(component)) {
    add('wiring_component_cmake', 'src/component.cmake not found.');
  } else {
    const cm = fs.readFileSync(component, 'utf8');
    if (!cm.includes(`CONFIG_${cfg}`)) add('wiring_component_cmake', `src/component.cmake has no branch for CONFIG_${cfg}.`);
    if (!cm.includes(`port/bsp/${chipset}`)) add('wiring_component_cmake', `src/component.cmake never adds port/bsp/${chipset} to STDK_SRC_PATH.`);
    if (!cm.includes(`include/bsp/${chipset}`)) add('wiring_component_cmake', `src/component.cmake never adds include/bsp/${chipset} to STDK_INCLUDE_PATH.`);
  }
  if (!fs.existsSync(custom)) {
    add('wiring_include_dir', `src/include/bsp/${chipset}/iot_bsp_custom.h does not exist.`);
  }

  // 3. identifiers, includes and symbols per source file
  const toResolve = new Set();
  const perFile = {};
  for (const [file, src] of Object.entries(sources)) {
    const local = localDefinitions(src.raw, src.stripped);
    const calls = new Set();
    const consts = new Set();
    for (const m of src.code.matchAll(/(?<![.>\w])([A-Za-z_]\w*)\s*\(/g)) calls.add(m[1]);
    for (const m of src.code.matchAll(/\b([A-Z][A-Z0-9_]{2,})\b/g)) consts.add(m[1]);
    // STDK-owned names: IOT_* constants/macros, plus iot_* functions and *_t types.
    // Plain lowercase iot_* tokens are usually local variables, so they are skipped.
    const iotTokens = [...new Set((src.code.match(/\b(?:IOT_|iot_)\w+/g) || [])
      .filter(t => t.startsWith('IOT_') || t.endsWith('_t') || calls.has(t)))];
    const includes = [...src.raw.matchAll(/^[ \t]*#\s*include\s*"([^"]+)"/gm)].map(m => m[1]);
    perFile[file] = { calls, consts, includes };

    // STDK-owned names must exist in src/include (or be defined in the file)
    for (const t of iotTokens) {
      if (!stdk.words.has(t) && !local.has(t)) {
        add('unknown_stdk_identifier', `'${t}' is not defined in any src/include header or in this file.`, file);
      }
    }
    for (const c of calls) if (!IGNORED_CALLS.has(c) && !/^(?:IOT_|iot_)/.test(c) && !local.has(c)) toResolve.add(c);
    for (const c of consts) if (!IGNORED_CALLS.has(c) && !/^IOT_/.test(c) && !local.has(c)) toResolve.add(c);
  }

  // 4. vendor checks (need the SDK)
  if (sdkDir) {
    const sdkHeaders = new Set(walk(sdkDir, n => n.endsWith('.h')).map(p => path.basename(p)));
    for (const [file, info] of Object.entries(perFile)) {
      for (const inc of info.includes) {
        const base = path.basename(inc);
        if (!sdkHeaders.has(base) && !stdk.basenames.has(base) && !fs.existsSync(path.join(portDir, inc))) {
          add('unknown_header', `#include "${inc}" was found in neither the vendor SDK nor STDK.`, file);
        }
      }
    }
    const candidates = [...toResolve].filter(w => !stdk.words.has(w));
    const found = grepKnownWords(candidates, [sdkDir, '/usr/include']);
    for (const [file, info] of Object.entries(perFile)) {
      for (const w of candidates) {
        if (found.has(w)) continue;
        if (info.calls.has(w) || info.consts.has(w)) {
          add('unknown_vendor_symbol',
            `'${w}' is used but defined nowhere in the SDK (or libc headers). Check the spelling, or find the real equivalent.`, file);
        }
      }
    }
  }

  // 5. vendor call arity: each call must match a declaration found in the SDK
  if (sdkDir) {
    const names = [...toResolve].filter(w => !stdk.words.has(w) && /^[a-z_]/.test(w));
    const decls = vendorParamCounts(names, sdkDir);
    for (const [file, src] of Object.entries(sources)) {
      for (const name of names) {
        const counts = decls[name];
        if (!counts || counts.size === 0) continue;
        const re = new RegExp(`(?<![.>\\w])${name}\\s*\\(`, 'g');
        for (const m of src.code.matchAll(re)) {
          const args = balancedParens(src.code, m.index + m[0].length - 1);
          if (args === null) continue;
          const n = args.trim() === '' ? 0 : splitTopLevel(args).length;
          if (!counts.has(n)) {
            add('vendor_call_arity', `${name}() is called with ${n} argument(s) but the SDK declares ${[...counts].join(' or ')} parameter(s). Re-read its declaration.`, file);
            break;
          }
        }
      }
    }
  }

  const result = {
    status: issues.length === 0 ? 'ok' : 'error',
    mode: 'verify',
    chipset,
    port_dir: portDir,
    summary: {
      required_files: files.length + 1,
      files_present: Object.keys(sources).length + (fs.existsSync(cmakeFile) ? 1 : 0),
      signatures_implemented: `${signaturesImplemented}/${signaturesTotal}`,
      errors: issues.length,
    },
    issues,
    skipped_checks: skipped,
    next_step: issues.length
      ? 'NOT DONE: fix every issue above, then re-run this command until it exits 0. Do not summarize the port as complete.'
      : 'Verifier passed. Paste this summary block in your final report, then compile each file with the SDK toolchain and do the manual review described in SKILL.md, Step 3.',
    note: 'Static text analysis only. This is not a compile, and it cannot verify argument types or vendor-call semantics. Compile each file separately (SKILL.md, Step 3).',
  };
  (issues.length ? console.error : console.log)(JSON.stringify(result, null, 2));
  process.exit(issues.length ? 1 : 0);
}

function main() {
  const params = parseArgs(process.argv.slice(2));
  const chipsetRaw = typeof params['chipset'] === 'string' ? params['chipset'] : '';

  if (chipsetRaw.trim() === '') {
    fail('missing_chipset_name', 'Chipset name is required.');
  }
  const chipset = chipsetRaw.trim().toLowerCase();

  if (params['verify']) {
    verify(chipset, params);
    return;
  }

  const supported = supportedChipsets();
  if (supported.includes(chipset)) {
    fail('already_supported',
      `'${chipset}' is already ported. See src/port/bsp/${chipset}/ for the existing implementation.`,
      { supported_chipsets: supported });
  }

  const firmwareLink = typeof params['firmware-link'] === 'string' ? params['firmware-link'].trim() : '';
  if (firmwareLink === '' || !isLikelyUrl(firmwareLink)) {
    fail('missing_or_invalid_firmware_link',
      'A valid firmware/SDK link (http/https URL) is required before any code can be generated. ' +
      'Ask the user for a link to the chipset SDK source or API documentation and re-run once provided. ' +
      'Do not generate any porting code without it.');
  }

  const { unclassified } = loadBspApi();
  console.log(JSON.stringify({
    status: 'ok',
    chipset,
    firmware_link: firmwareLink,
    target_dir: `src/port/bsp/${chipset}/`,
    files: [
      ...requiredFiles(chipset),
      { file: 'CMakeLists.txt', required_signatures: [] },
    ],
    ...(unclassified.length ? { unclassified_apis: unclassified } : {}),
    also_required: [
      `src/Kconfig: 'config STDK_IOT_CORE_BSP_SUPPORT_${chipset.toUpperCase()}' in the STDK_IOT_CORE_BSP_SUPPORT choice`,
      `src/component.cmake: a CONFIG_STDK_IOT_CORE_BSP_SUPPORT_${chipset.toUpperCase()} branch adding port/bsp/${chipset} and include/bsp/${chipset}`,
      `src/include/bsp/${chipset}/iot_bsp_custom.h`,
    ],
    instructions: 'Before writing code, confirm the cloned SDK actually targets this chipset, then grep it for every ' +
      'vendor function, constant and header you plan to use. Write a complete, working implementation for every listed ' +
      'signature (no TODO/stub bodies), using src/port/bsp/esp32/ as a structural reference, and add the wiring listed ' +
      'in also_required. Finish by running this script with --verify --sdk-dir <cloned SDK> and fix every error, then compile ' +
      'each file with the SDK toolchain (see SKILL.md, Step 3).',
  }, null, 2));
}

main();
