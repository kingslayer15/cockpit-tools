//! WorkBuddy / CodeBuddy CN 登录态的 **at-rest 字段解密**（`$wbEncrypted` 信封）。
//!
//! ## 为什么需要这个模块
//!
//! WorkBuddy 5.3.13 起（延续到 5.6.0），客户端写的
//! `%LOCALAPPDATA%\CodeBuddyExtension\Data\Public\auth\workbuddy-desktop.info`
//! 里的凭据节点被换成字段级加密信封：
//!
//! ```json
//! "accessToken": {"$wbEncrypted": 1, "envelope": "<base64>"}
//! // envelope 解码后：{"suite":1,"keyId":"…","nonce":"…","authTag":"…","ciphertext":"…"}
//! ```
//!
//! 于是 `auth.accessToken` 从**字符串**变成**对象**，`parse_local_access_token`
//! 只取 `Value::as_str()` → 返回 `None` → 导入本机登录态报「未找到 access token」。
//! CodeBuddy CN 的 safeStorage 解出的 JSON 若升级采用同一信封机制，走同一解密路径。
//!
//! 这个模块负责把信封就地解回字符串。**兼容性**：只有对象才走解密，明文 `string`
//! 节点原样保留（上游 `ProtectedFieldCodec.decodeString` 对字符串直接返回），所以
//! 旧版明文 `.info` / safeStorage 数据完全无副作用（`Ok(0)`）。
//!
//! ## 加密链路（AES-256-GCM，端到端验证过）
//!
//! ```text
//! key   = SHA256(atRestSecretKey)          # atRestSecretKey = canonical base64(32B)，44 字符
//! keyId = SHA256(key).hex()[:16]
//! AAD   = "WB-AAD\0" ‖ 01 ‖ LP("WBEV1") ‖ LP("sym-v1") ‖ BE32(suite) ‖ LP(keyId) ‖ 02 ‖ 00 ‖ 00
//!          （LP = BE32(len)‖utf8；field 模式 framing=2；scheme="sym-v1"；
//!           末两字节是 sequence / final 的 encodeOptionalUint64(undefined) = 0，⚠ 不是 1）
//! 明文  = AES-256-GCM(key, nonce).open(ciphertext ‖ authTag, AAD)
//! ```
//!
//! ## 密钥从哪来
//!
//! `atRestSecretKey` 由客户端主进程的 native 层提供（改造版 Electron 的
//! `workbuddyStorage.loggerGet()`）——不落磁盘明文，`~/.workbuddy/keyblob`
//! 又是**被它封装**的 ⇒ 磁盘上没有可解出它的东西，它只在客户端主进程内存里。
//!
//! 取钥四级：
//! 1. 进程内 memo（一次导入多个字段只取一次）；
//! 2. 磁盘缓存 `<data_dir>/at_rest_key.json`（按 keyId 自校验，上游换钥自动失效）；
//! 3. 扫客户端主进程内存（只读：`OpenProcess`/`VirtualQueryEx`/`ReadProcessMemory`，
//!    不挂调试器、不注入、不写目标进程），按启动时间升序，keyId 自校验命中；
//! 4. 第 3 步被拒（`ERROR_ACCESS_DENIED`，目标以管理员身份运行）→ 用同一个 exe
//!    起一个**提权实例**（`--at-rest-scan-key=<keyId>`，弹一次 UAC）替我们扫并落盘缓存。
//!
//! 提权只需一次：密钥落盘后，普通权限启动直接命中缓存。静态钥跨重启稳定
//! （判据：keyblob 在多次重启后未被重写）。
//!
//! 方案移植自 KeyBuddy 的 `at_rest.rs`（2026-09-20 在本机端到端验证 8/8 字段解出），
//! 进程扫描名单扩展为 WorkBuddy.exe / CodeBuddy CN.exe / CodeBuddy.exe ——
//! 命中判据是 keyId 自校验，扫错进程不会取到错钥。

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine as _;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

/// 信封标记：节点是对象且带这个字段才算受保护节点
const ENVELOPE_MARK: &str = "$wbEncrypted";

/// 进程内 memo：同一个 keyId 只取一次钥（一次导入可能有 8 个字段 / 多次导入）。
/// 值只在内存里，不参与日志。
fn memo() -> &'static Mutex<HashMap<String, String>> {
    static M: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
    M.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 一份信封（`envelope` base64 解码后的 JSON）
#[derive(Debug)]
struct Envelope {
    suite: u32,
    key_id: String,
    nonce: Vec<u8>,
    auth_tag: Vec<u8>,
    ciphertext: Vec<u8>,
}

/// 把 JSON 里**所有** `{$wbEncrypted:1, envelope}` 节点就地解密成字符串。
///
/// 返回解出的字段数。语义约定：
/// - 没有受保护节点 → `Ok(0)`（旧版明文格式，正常情况）；
/// - 有节点且至少解出一个 → `Ok(n)`（个别字段失败不报错，不阻断整体导入）；
/// - 有节点但**一个都没解出** → `Err(人话原因)`，让上层把真实原因显示出来
///   （而不是误导性的「未找到 access token」）。
pub fn decrypt_json_in_place(v: &mut Value, data_dir: &Path) -> Result<usize, String> {
    let mut spots: Vec<(String, String, u32)> = Vec::new();
    collect(v, String::new(), &mut spots);
    if spots.is_empty() {
        return Ok(0);
    }

    let mut done = 0usize;
    let mut first_err: Option<String> = None;
    for (ptr, key_id, suite) in spots {
        let env = match read_envelope(&key_id, suite, v, &ptr) {
            Ok(e) => e,
            Err(e) => {
                first_err.get_or_insert(e);
                continue;
            }
        };
        match decrypt_envelope(&env, data_dir) {
            Ok(text) => {
                if let Some(slot) = v.pointer_mut(&ptr) {
                    *slot = Value::String(text);
                    done += 1;
                }
            }
            Err(e) => {
                first_err.get_or_insert(e);
            }
        }
    }

    if done == 0 {
        if let Some(e) = first_err {
            return Err(e);
        }
    }
    Ok(done)
}

/// 递归收集受保护节点的 JSON Pointer 与它的 keyId。
fn collect(node: &Value, ptr: String, out: &mut Vec<(String, String, u32)>) {
    match node {
        Value::Object(m) => {
            if m.get(ENVELOPE_MARK).and_then(Value::as_u64) == Some(1) {
                if let Some(env) = m.get("envelope").and_then(Value::as_str) {
                    if let Ok(parsed) = parse_envelope(env) {
                        out.push((ptr, parsed.key_id, parsed.suite));
                    }
                }
                return;
            }
            for (k, val) in m {
                collect(val, format!("{ptr}/{}", escape_ptr(k)), out);
            }
        }
        Value::Array(arr) => {
            for (i, val) in arr.iter().enumerate() {
                collect(val, format!("{ptr}/{i}"), out);
            }
        }
        _ => {}
    }
}

/// JSON Pointer 转义（RFC 6901）：`~` → `~0`，`/` → `~1`
fn escape_ptr(k: &str) -> String {
    k.replace('~', "~0").replace('/', "~1")
}

/// 从树里把某个指针位置的 `envelope` 取出来解析（避免 collect 阶段复制大字符串）
fn read_envelope(key_id: &str, suite: u32, root: &Value, ptr: &str) -> Result<Envelope, String> {
    let b64 = root
        .pointer(&format!("{ptr}/envelope"))
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{ptr} 的 envelope 不是字符串"))?;
    let mut env = parse_envelope(b64)?;
    env.key_id = key_id.to_string();
    env.suite = suite;
    Ok(env)
}

fn parse_envelope(b64: &str) -> Result<Envelope, String> {
    let raw = b64_decode(b64).map_err(|_| "envelope 不是合法 base64".to_string())?;
    let v: Value = serde_json::from_slice(&raw)
        .map_err(|e| format!("envelope 解码后不是 JSON（{} 字节）: {e}", raw.len()))?;
    let get_str = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
    Ok(Envelope {
        suite: v.get("suite").and_then(Value::as_u64).unwrap_or(1) as u32,
        key_id: get_str("keyId").ok_or("envelope 缺少 keyId")?,
        nonce: b64_decode(&get_str("nonce").ok_or("envelope 缺少 nonce")?)
            .map_err(|_| "envelope.nonce 不是合法 base64".to_string())?,
        auth_tag: b64_decode(&get_str("authTag").ok_or("envelope 缺少 authTag")?)
            .map_err(|_| "envelope.authTag 不是合法 base64".to_string())?,
        ciphertext: b64_decode(&get_str("ciphertext").ok_or("envelope 缺少 ciphertext")?)
            .map_err(|_| "envelope.ciphertext 不是合法 base64".to_string())?,
    })
}

fn decrypt_envelope(env: &Envelope, data_dir: &Path) -> Result<String, String> {
    let secret = secret_for(&env.key_id, data_dir)?;
    let key = sha256(secret.as_bytes());
    let mut buf = env.ciphertext.clone();
    // ⚠ `aes-gcm` 的 `Aead::decrypt` 要求 `密文‖tag` 拼接；信封里 authTag 是独立字段
    // （Node 的 `setAuthTag` 口径）—— 不拼会稳定 InvalidTag。
    buf.extend_from_slice(&env.auth_tag);
    // AAD 必须走 `Payload` 传：直接 `decrypt(nonce, msg)` 是**空 AAD**，
    // 结果是"密文能解出来、但没做任何认证"。
    let aad = build_aad(&env.key_id, env.suite);
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| format!("密钥长度不对: {e}"))?;
    let pt = cipher
        .decrypt(
            Nonce::from_slice(&env.nonce),
            Payload {
                msg: buf.as_slice(),
                aad: &aad,
            },
        )
        .map_err(|_| {
            "at-rest 字段解密失败（InvalidTag）：本机密钥与密文不匹配，可能是 \
             客户端升级换了钥 —— 重试会自动重扫；若仍失败请重启客户端后再导入"
                .to_string()
        })?;
    String::from_utf8(pt).map_err(|e| format!("解密结果不是 UTF-8: {e}"))
}

/// 取 `atRestSecretKey`（44 字符 canonical base64）。四级：
/// 内存 memo → 磁盘缓存 → 扫进程内存 → **自提权重扫**（唯一会弹 UAC 的一步）。
fn secret_for(key_id: &str, data_dir: &Path) -> Result<String, String> {
    if let Some(s) = memo().lock().unwrap().get(key_id).cloned() {
        return Ok(s);
    }
    if let Some(s) = load_cache(data_dir, key_id) {
        remember(key_id, &s);
        return Ok(s);
    }
    match memory::scan_for_secret(key_id) {
        ScanOutcome::Found(s) => {
            save_cache(data_dir, key_id, &s);
            remember(key_id, &s);
            Ok(s)
        }
        // 有客户端进程，但它是高完整性令牌（以管理员身份运行）——普通权限读不进去。
        // 起一个提权实例替我们扫，密钥经缓存回传；UAC 只需点这一次，之后永远命中缓存。
        ScanOutcome::NeedElevation => {
            run_elevated_helper(key_id)?;
            match load_cache(data_dir, key_id) {
                Some(s) => {
                    remember(key_id, &s);
                    Ok(s)
                }
                None => Err(
                    "已请求管理员权限扫描客户端内存，但仍没取到密钥。\
                     请确认 WorkBuddy / CodeBuddy CN 客户端正在运行，然后重试。"
                        .into(),
                ),
            }
        }
        ScanOutcome::NotFound(e) => Err(format!(
            "登录态已被客户端加密，且本机取不到解密密钥（{e}）。\
             请启动 WorkBuddy / CodeBuddy CN 客户端后重试 —— 密钥只在它的主进程内存里，不落磁盘。"
        )),
    }
}

fn remember(key_id: &str, secret: &str) {
    memo()
        .lock()
        .unwrap()
        .insert(key_id.to_string(), secret.to_string());
}

/// 扫内存取钥的结果。
///
/// 「没找到」和「权限不够」必须分开：前者要报给用户（通常是客户端没开），
/// 后者要触发一次提权重扫。
pub enum ScanOutcome {
    Found(String),
    /// 有客户端进程但读不进去（目标完整性级别更高）
    NeedElevation,
    NotFound(String),
}

// ---------- 缓存 ----------

/// `<data_dir>/at_rest_key.json` = `{"keyId": "...", "secret": "..."}`。
///
/// 与账号数据同级、同等敏感（那里面本来就存 token 明文），所以不额外加密；
/// 但**绝不写进日志**。按 keyId 校验：上游换钥后旧条目自动失效。
fn cache_path(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join("at_rest_key.json")
}

fn load_cache(data_dir: &Path, key_id: &str) -> Option<String> {
    let text = std::fs::read_to_string(cache_path(data_dir)).ok()?;
    let v: Value = serde_json::from_str(&text).ok()?;
    if v.get("keyId").and_then(Value::as_str) != Some(key_id) {
        return None;
    }
    let secret = v.get("secret").and_then(Value::as_str)?.to_string();
    // 自校验：缓存被改动/损坏时不能让整条链静默给出错误结果
    if key_id_of(&secret) != key_id {
        return None;
    }
    Some(secret)
}

fn save_cache(data_dir: &Path, key_id: &str, secret: &str) {
    let doc = serde_json::json!({ "keyId": key_id, "secret": secret });
    // 缓存写失败不是错误：下次再扫一遍内存即可（只是慢一点）
    let _ = std::fs::create_dir_all(data_dir);
    if let Ok(text) = serde_json::to_string_pretty(&doc) {
        let _ = std::fs::write(cache_path(data_dir), text);
    }
}

// ---------- 基础工具 ----------

fn b64_decode(s: &str) -> Result<Vec<u8>, ()> {
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|_| ())
}

/// `keyId = SHA256(SHA256(secret)).hex()[:16]`（secret 按 utf8 原文参与哈希）
fn key_id_of(secret: &str) -> String {
    let key = sha256(secret.as_bytes());
    to_hex(&sha256(&key))[..16].to_string()
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

fn to_hex(b: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push(HEX[(x >> 4) as usize] as char);
        s.push(HEX[(x & 0xf) as usize] as char);
    }
    s
}

/// `LP(x)` = `BE32(len) ‖ utf8(x)`
fn lp(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
}

/// AAD：`"WB-AAD\0" ‖ 01 ‖ LP("WBEV1") ‖ LP("sym-v1") ‖ BE32(suite) ‖ LP(keyId) ‖ 02 ‖ 00 ‖ 00`
fn build_aad(key_id: &str, suite: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(96);
    aad.extend_from_slice(b"WB-AAD\x00");
    aad.push(1); // 结构版本
    lp(&mut aad, "WBEV1"); // framing
    lp(&mut aad, "sym-v1"); // scheme
    aad.extend_from_slice(&suite.to_be_bytes());
    lp(&mut aad, key_id);
    aad.push(2); // FRAMING_CODE[field]
    aad.push(0); // sequence 未定义
    aad.push(0); // final 未定义（`void 0===es.final ? 0 : …` → 0，不是 1）
    aad
}

// ---------- 客户端主进程内存取钥（只读） ----------

#[cfg(windows)]
mod memory {
    use super::{key_id_of, ScanOutcome};
    use std::ffi::c_void;

    /// 单个进程扫描的失败原因：**必须**把「权限不够」和「别的错」分开，
    /// 前者要触发提权重扫，后者只是记录（比如某个进程刚好退出）。
    enum PidErr {
        AccessDenied,
        Other(String),
    }

    const TH32CS_SNAPPROCESS: u32 = 0x0000_0002;
    const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
    const PROCESS_VM_READ: u32 = 0x0010;
    const MEM_COMMIT: u32 = 0x1000;
    const MAX_PATH: usize = 260;
    const CHUNK: usize = 4 * 1024 * 1024;
    /// 单个进程最多读多少（正常客户端主进程 0.3~1 GB）
    const MAX_SCAN_BYTES: usize = 3 * 1024 * 1024 * 1024;
    /// 跨 chunk 边界的候选：每个 chunk 与上一块尾部重叠这么多字节
    const OVERLAP: usize = 64;

    /// 可读的页保护位
    const READABLE: [u32; 6] = [0x02, 0x04, 0x08, 0x20, 0x40, 0x80];

    /// 可能持有 at-rest 密钥的客户端进程名（同为腾讯系 Electron fork，
    /// 命中判据是 keyId 自校验，名单多列不会取错钥）。
    const CANDIDATE_PROCESS_NAMES: [&str; 3] =
        ["WorkBuddy.exe", "CodeBuddy CN.exe", "CodeBuddy.exe"];

    #[repr(C)]
    struct ProcessEntry32W {
        dw_size: u32,
        cnt_usage: u32,
        th32_process_id: u32,
        th32_default_heap_id: usize,
        th32_module_id: u32,
        cnt_threads: u32,
        th32_parent_process_id: u32,
        pc_pri_class_base: i32,
        dw_flags: u32,
        sz_exe_file: [u16; MAX_PATH],
    }

    #[repr(C)]
    struct MemoryBasicInformation {
        base_address: *mut c_void,
        allocation_base: *mut c_void,
        allocation_protect: u32,
        region_size: usize,
        state: u32,
        protect: u32,
        _type: u32,
    }

    #[repr(C)]
    struct FileTime {
        low: u32,
        high: u32,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> *mut c_void;
        fn Process32FirstW(snap: *mut c_void, entry: *mut ProcessEntry32W) -> i32;
        fn Process32NextW(snap: *mut c_void, entry: *mut ProcessEntry32W) -> i32;
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut c_void;
        fn CloseHandle(h: *mut c_void) -> i32;
        fn GetProcessTimes(
            h: *mut c_void,
            creation: *mut FileTime,
            exit: *mut FileTime,
            kernel: *mut FileTime,
            user: *mut FileTime,
        ) -> i32;
        fn VirtualQueryEx(
            h: *mut c_void,
            addr: *const c_void,
            mbi: *mut MemoryBasicInformation,
            len: usize,
        ) -> usize;
        fn ReadProcessMemory(
            h: *mut c_void,
            addr: *const c_void,
            buf: *mut c_void,
            size: usize,
            read: *mut usize,
        ) -> i32;
        fn GetLastError() -> u32;
    }

    fn handle_ok(h: *mut c_void) -> bool {
        !h.is_null() && h as isize != -1
    }

    fn is_candidate_process(name: &str) -> bool {
        CANDIDATE_PROCESS_NAMES
            .iter()
            .any(|n| name.eq_ignore_ascii_case(n))
    }

    /// 枚举客户端进程，**按启动时间升序** —— 主进程一定比它的渲染/工具子进程
    /// 先启动，所以顺序即"最可能是持钥者优先"。同一个可执行文件跑多个实例时也不会取错：
    /// 命中的判据是 keyId 自校验。
    fn candidate_pids() -> Vec<u32> {
        let mut out: Vec<(i64, u32)> = Vec::new();
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if !handle_ok(snap) {
                return Vec::new();
            }
            let mut entry: ProcessEntry32W = std::mem::zeroed();
            entry.dw_size = std::mem::size_of::<ProcessEntry32W>() as u32;
            if Process32FirstW(snap, &mut entry) != 0 {
                loop {
                    let n = entry
                        .sz_exe_file
                        .iter()
                        .position(|c| *c == 0)
                        .unwrap_or(MAX_PATH);
                    let name = String::from_utf16_lossy(&entry.sz_exe_file[..n]);
                    if is_candidate_process(&name) {
                        let pid = entry.th32_process_id;
                        let h = OpenProcess(PROCESS_QUERY_INFORMATION, 0, pid);
                        let mut t = 0i64;
                        if handle_ok(h) {
                            let mut c = FileTime { low: 0, high: 0 };
                            let mut e = FileTime { low: 0, high: 0 };
                            let mut k = FileTime { low: 0, high: 0 };
                            let mut u = FileTime { low: 0, high: 0 };
                            if GetProcessTimes(h, &mut c, &mut e, &mut k, &mut u) != 0 {
                                t = (((c.high as i64) << 32) | c.low as i64) & i64::MAX;
                            }
                            CloseHandle(h);
                        }
                        out.push((t, pid));
                    }
                    entry.dw_size = std::mem::size_of::<ProcessEntry32W>() as u32;
                    if Process32NextW(snap, &mut entry) == 0 {
                        break;
                    }
                }
            }
            CloseHandle(snap);
        }
        out.sort_by_key(|(t, _)| *t);
        out.into_iter().map(|(_, p)| p).collect()
    }

    /// 在目标进程里找 keyId 匹配的 44 字符 canonical base64。
    ///
    /// 全程**只读**：不挂调试器、不注入、不写目标进程、不 suspend 线程。
    fn scan_pid(pid: u32, key_id: &str) -> Result<Option<String>, PidErr> {
        unsafe {
            let h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
            if !handle_ok(h) {
                let code = GetLastError();
                // 5 = ERROR_ACCESS_DENIED：目标完整性级别更高（客户端以管理员身份运行时
                // 必然如此）。这不是"没找到"，是"需要提权再扫"。
                return Err(if code == 5 {
                    PidErr::AccessDenied
                } else {
                    PidErr::Other(format!("打开进程失败（Win32 {code}）"))
                });
            }
            let mut mbi: MemoryBasicInformation = std::mem::zeroed();
            let mut addr: usize = 0;
            let mut total: usize = 0;
            let mut tail: Vec<u8> = Vec::new();
            let mut found: Option<String> = None;
            loop {
                if found.is_some() {
                    break;
                }
                if VirtualQueryEx(
                    h,
                    addr as *const c_void,
                    &mut mbi,
                    std::mem::size_of::<MemoryBasicInformation>(),
                ) == 0
                {
                    break;
                }
                let base = mbi.base_address as usize;
                let size = mbi.region_size;
                if mbi.state == MEM_COMMIT && READABLE.contains(&mbi.protect) && size > 0 {
                    let mut off = 0usize;
                    while off < size {
                        if total >= MAX_SCAN_BYTES {
                            break;
                        }
                        let n = CHUNK.min(size - off);
                        let mut buf = vec![0u8; n];
                        let mut got: usize = 0;
                        if ReadProcessMemory(
                            h,
                            (base + off) as *const c_void,
                            buf.as_mut_ptr() as *mut c_void,
                            n,
                            &mut got,
                        ) != 0
                            && got > 0
                        {
                            buf.truncate(got);
                            total += got;
                            // 拼上一块尾巴：44 字符的候选可能正好跨 chunk 边界
                            let mut view = tail.clone();
                            view.extend_from_slice(&buf);
                            if let Some(s) = find_secret(&view, key_id) {
                                found = Some(s);
                                break;
                            }
                            let keep = buf.len().min(OVERLAP);
                            tail = buf[buf.len() - keep..].to_vec();
                        }
                        off += n;
                    }
                }
                let next = base + size;
                if next <= addr {
                    break;
                }
                addr = next;
                if addr > 0x7FFF_FFFF_0000 {
                    break;
                }
            }
            CloseHandle(h);
            Ok(found)
        }
    }

    /// 在内存缓冲里找 `[A-Za-z0-9+/]{43}=` 且 `keyId` 自校验通过的串。
    ///
    /// 手写扫描而不是引 `regex`：候选量大（任意 44 字符 base64 都算），
    /// 一次性顺着字节走 + 只在长度恰好 44 时算一次 SHA256，比正则引擎便宜得多。
    fn find_secret(buf: &[u8], key_id: &str) -> Option<String> {
        let is_b64 = |b: u8| b.is_ascii_alphanumeric() || b == b'+' || b == b'/';
        let mut i = 0usize;
        while i < buf.len() {
            if !is_b64(buf[i]) {
                i += 1;
                continue;
            }
            let start = i;
            while i < buf.len() && is_b64(buf[i]) {
                i += 1;
            }
            // 候选＝**43 个 base64 字符 + 恰好一个 `=`**（32 字节的 canonical base64，共 44 字符）。
            // 前后边界要卡住：`=` 之后不能再是 base64 字符或 `=`。
            let len = i - start;
            if len == 43 && i < buf.len() && buf[i] == b'=' {
                let after_ok = i + 1 >= buf.len() || (!is_b64(buf[i + 1]) && buf[i + 1] != b'=');
                if after_ok {
                    let cand = &buf[start..i + 1];
                    if let Ok(s) = std::str::from_utf8(cand) {
                        if key_id_of(s) == key_id {
                            return Some(s.to_string());
                        }
                    }
                }
            }
        }
        None
    }

    /// 扫全部客户端进程，命中即停。
    ///
    /// 只有**所有**可读进程都扫过且没命中时才算「没找到」；一旦出现「拒访」，
    /// 判为「需要提权」—— 密钥几乎必然在被拒的那个主进程里。
    pub fn scan_for_secret(key_id: &str) -> ScanOutcome {
        let pids = candidate_pids();
        if pids.is_empty() {
            return ScanOutcome::NotFound(
                "没找到 WorkBuddy / CodeBuddy CN 客户端进程".into(),
            );
        }
        let mut denied = 0usize;
        let mut notes: Vec<String> = Vec::new();
        for pid in &pids {
            match scan_pid(*pid, key_id) {
                Ok(Some(s)) => return ScanOutcome::Found(s),
                Ok(None) => {}
                Err(PidErr::AccessDenied) => denied += 1,
                Err(PidErr::Other(e)) => notes.push(format!("pid {pid}: {e}")),
            }
        }
        if denied > 0 {
            return ScanOutcome::NeedElevation;
        }
        ScanOutcome::NotFound(if notes.is_empty() {
            format!(
                "已扫描 {} 个客户端进程（pid {}）但未找到本机密钥",
                pids.len(),
                pids.iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join("/")
            )
        } else {
            notes.join("；")
        })
    }
}

#[cfg(not(windows))]
mod memory {
    use super::ScanOutcome;

    pub fn scan_for_secret(_key_id: &str) -> ScanOutcome {
        ScanOutcome::NotFound("at-rest 取钥目前只有 Windows 实现".into())
    }
}

// ---------- 自提权取钥（唯一会弹 UAC 的一步） ----------

/// 助手模式参数：`Cockpit Tools.exe --at-rest-scan-key=<keyId>`
const HELPER_FLAG: &str = "--at-rest-scan-key";

/// 应用数据目录，与 Tauri `app_data_dir()` 同口径。
///
/// 助手实例（提权）不经过 Tauri 初始化，所以独立算一次，确保两边读写的是同一个
/// `at_rest_key.json`。
pub fn data_dir() -> std::path::PathBuf {
    #[cfg(target_os = "windows")]
    {
        match std::env::var("APPDATA") {
            Ok(a) if !a.is_empty() => {
                return std::path::PathBuf::from(a).join("com.jlcodes.cockpit-tools");
            }
            _ => {}
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Some(home) = dirs::home_dir() {
            return home
                .join("Library")
                .join("Application Support")
                .join("com.jlcodes.cockpit-tools");
        }
    }
    #[cfg(all(not(windows), not(target_os = "macos")))]
    {
        if let Some(cfg) = dirs::config_dir() {
            return cfg.join("com.jlcodes.cockpit-tools");
        }
    }
    std::path::PathBuf::from("data")
}

/// 从命令行里解析助手模式的 keyId（纯函数，便于测试）。
fn parse_helper_arg<I: IntoIterator<Item = String>>(args: I) -> Option<String> {
    args.into_iter().find_map(|a| {
        a.strip_prefix(HELPER_FLAG)
            .map(|rest| rest.trim_start_matches('=').trim().to_string())
            .filter(|s| !s.is_empty())
    })
}

/// 助手模式：只做「扫内存取钥 + 落盘缓存」然后退出 —— **不初始化 Tauri、不起界面**。
///
/// 返回 `Some(退出码)` 表示当前进程是助手实例，调用方（`lib::run`）应立即退出。
/// 必须抢在单实例插件之前判断，否则提权实例会把参数转发给已运行的主实例然后退出，
/// 密钥永远扫不到。
pub fn try_helper_mode() -> Option<i32> {
    let key_id = parse_helper_arg(std::env::args())?;
    let dir = data_dir();
    Some(match memory::scan_for_secret(&key_id) {
        ScanOutcome::Found(s) => {
            save_cache(&dir, &key_id, &s);
            0
        }
        _ => 1,
    })
}

#[cfg(not(windows))]
fn run_elevated_helper(_key_id: &str) -> Result<(), String> {
    Err("at-rest 取钥目前只有 Windows 实现".into())
}

/// 用同一个 exe 起一个提权实例去扫内存（UAC 弹一次）。
///
/// 不自己重启整个 app：GUI 已经起来了，重启会丢窗口状态；"再起一个同 exe 的实例，
/// 只干活、不进界面、把结果写进缓存"是最小侵入的做法。
#[cfg(windows)]
fn run_elevated_helper(key_id: &str) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;

    if is_elevated() {
        return Err(
            "已以管理员身份运行，但仍读不到客户端内存 —— 请确认 WorkBuddy / CodeBuddy CN 正在运行后重试"
                .into(),
        );
    }
    let exe = std::env::current_exe().map_err(|e| format!("定位自身程序失败：{e}"))?;
    let verb: Vec<u16> = "runas".encode_utf16().chain(std::iter::once(0)).collect();
    let file: Vec<u16> = exe
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let params: Vec<u16> = format!("{HELPER_FLAG}={key_id}")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let mut sei: ShellExecuteInfoW = std::mem::zeroed();
        sei.cb_size = std::mem::size_of::<ShellExecuteInfoW>() as u32;
        sei.f_mask = SEE_MASK_NOCLOSEPROCESS;
        sei.lp_verb = verb.as_ptr();
        sei.lp_file = file.as_ptr();
        sei.lp_parameters = params.as_ptr();
        sei.n_show = 1; // SW_SHOWNORMAL
        if ShellExecuteExW(&mut sei) == 0 {
            let code = GetLastError();
            // 1223 = ERROR_CANCELLED：用户在 UAC 弹窗里点了"否"
            return Err(if code == 1223 {
                "读取客户端密钥需要一次管理员授权（UAC），刚才被取消了。\
                 请再点一次导入，并在系统弹窗里选「是」。"
                    .into()
            } else {
                format!("以管理员身份启动取钥助手失败（Win32 {code}）")
            });
        }
        // 等它扫完（首次扫百 MB~GB 级内存，正常十几秒）；超时也继续去读缓存，
        // 因为助手可能已经写完了。
        if !sei.h_process.is_null() {
            WaitForSingleObject(sei.h_process, 180_000);
            CloseHandle(sei.h_process);
        }
    }
    Ok(())
}

#[cfg(windows)]
#[repr(C)]
struct ShellExecuteInfoW {
    cb_size: u32,
    f_mask: u32,
    hwnd: *mut std::ffi::c_void,
    lp_verb: *const u16,
    lp_file: *const u16,
    lp_parameters: *const u16,
    lp_directory: *const u16,
    n_show: i32,
    h_inst_app: *mut std::ffi::c_void,
    lp_id_list: *mut std::ffi::c_void,
    lp_class: *const u16,
    hkey_class: *mut std::ffi::c_void,
    dw_hot_key: u32,
    h_icon_or_monitor: *mut std::ffi::c_void,
    h_process: *mut std::ffi::c_void,
}

#[cfg(windows)]
const SEE_MASK_NOCLOSEPROCESS: u32 = 0x0000_0040;

#[cfg(windows)]
#[link(name = "shell32")]
extern "system" {
    fn ShellExecuteExW(info: *mut ShellExecuteInfoW) -> i32;
}

#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    fn WaitForSingleObject(handle: *mut std::ffi::c_void, ms: u32) -> u32;
    fn GetCurrentProcess() -> *mut std::ffi::c_void;
    fn GetLastError() -> u32;
    fn CloseHandle(handle: *mut std::ffi::c_void) -> i32;
}

#[cfg(windows)]
#[link(name = "advapi32")]
extern "system" {
    fn OpenProcessToken(
        process: *mut std::ffi::c_void,
        access: u32,
        token: *mut *mut std::ffi::c_void,
    ) -> i32;
    fn GetTokenInformation(
        token: *mut std::ffi::c_void,
        class: u32,
        info: *mut std::ffi::c_void,
        len: u32,
        ret: *mut u32,
    ) -> i32;
}

/// 当前进程是否已提权（`TokenElevation`）。用来给出准确提示、避免无意义的 UAC。
#[cfg(windows)]
fn is_elevated() -> bool {
    unsafe {
        let mut tok: *mut std::ffi::c_void = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), 0x0008 /* TOKEN_QUERY */, &mut tok) == 0 {
            return false;
        }
        let mut elev: u32 = 0;
        let mut ret: u32 = 0;
        let ok = GetTokenInformation(
            tok,
            20, // TokenElevation
            &mut elev as *mut u32 as *mut std::ffi::c_void,
            std::mem::size_of::<u32>() as u32,
            &mut ret,
        );
        CloseHandle(tok);
        ok != 0 && elev != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 助手模式的参数解析：只有带 `--at-rest-scan-key=<keyId>` 才算助手实例。
    /// 这条判断错了的后果很严重 —— 正常启动被当成助手会**直接退出（界面都不出）**。
    #[test]
    fn helper_flag_parsing_is_strict() {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert_eq!(
            parse_helper_arg(s(&["app.exe", "--at-rest-scan-key=9127dea1b44020a7"])),
            Some("9127dea1b44020a7".to_string())
        );
        // 正常启动（可能带 tauri / deep-link 的各种参数）绝不能被识别成助手
        assert_eq!(parse_helper_arg(s(&["app.exe"])), None);
        assert_eq!(parse_helper_arg(s(&["app.exe", "--flag"])), None);
        assert_eq!(parse_helper_arg(s(&["--at-rest-scan-key"])), None);
        assert_eq!(parse_helper_arg(s(&["--at-rest-scan-key="])), None);
    }

    /// 数据目录口径必须与 Tauri `app_data_dir()` 一致（助手实例独立算一次），
    /// 否则提权实例会把缓存写到别处，主进程读不到 → 白弹一次 UAC。
    #[cfg(windows)]
    #[test]
    fn data_dir_matches_tauri_layout() {
        let d = data_dir();
        let last = d.file_name().and_then(|s| s.to_str()).unwrap_or("");
        assert_eq!(last, "com.jlcodes.cockpit-tools", "data_dir={}", d.display());
    }

    /// AAD 的逐字节形态是这条链路上**唯一**读反过一次的地方，钉死它。
    #[test]
    fn aad_layout_is_pinned() {
        let aad = build_aad("9127dea1b44020a7", 1);
        let mut want: Vec<u8> = Vec::new();
        want.extend_from_slice(b"WB-AAD\x00");
        want.push(0x01);
        want.extend_from_slice(&[0, 0, 0, 5]);
        want.extend_from_slice(b"WBEV1");
        want.extend_from_slice(&[0, 0, 0, 6]);
        want.extend_from_slice(b"sym-v1");
        want.extend_from_slice(&[0, 0, 0, 1]);
        want.extend_from_slice(&[0, 0, 0, 16]);
        want.extend_from_slice(b"9127dea1b44020a7");
        want.extend_from_slice(&[0x02, 0x00, 0x00]);
        assert_eq!(aad, want);
        // 7(WB-AAD\0)+1+9(LP WBEV1)+10(LP sym-v1)+4(suite)+20(LP keyId)+3 = 54
        assert_eq!(aad.len(), 54);
    }

    /// keyId 派生：`SHA256(SHA256(secret)).hex()[:16]`
    #[test]
    fn key_id_derivation_is_stable() {
        let s = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let k = sha256(s.as_bytes());
        assert_eq!(key_id_of(s), to_hex(&sha256(&k))[..16]);
        assert_eq!(key_id_of(s).len(), 16);
        assert!(key_id_of(s).chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// 明文节点不许被当成受保护节点（旧版格式向后兼容的核心保证）
    #[test]
    fn plaintext_json_is_untouched() {
        let dir = std::env::temp_dir().join(format!("ct-atrest-{}", std::process::id()));
        let mut v = serde_json::json!({"auth": {"accessToken": "eyJhbGciOi.abc.def"}});
        assert_eq!(decrypt_json_in_place(&mut v, &dir).unwrap(), 0);
        assert_eq!(v["auth"]["accessToken"], "eyJhbGciOi.abc.def");
    }

    /// 有信封但取不到钥 → 明确报错（而不是静默留空 / 报"未找到 access token"）
    #[test]
    fn envelope_without_key_reports_real_reason() {
        let dir = std::env::temp_dir().join(format!("ct-atrest-nokey-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // 一个结构合法但密钥永远取不到（keyId 是假的）的信封
        let env = base64::engine::general_purpose::STANDARD.encode(
            serde_json::json!({
                "suite": 1,
                "keyId": "0000000000000000",
                "nonce": base64::engine::general_purpose::STANDARD.encode([0u8; 12]),
                "authTag": base64::engine::general_purpose::STANDARD.encode([0u8; 16]),
                "ciphertext": base64::engine::general_purpose::STANDARD.encode([0u8; 8]),
            })
            .to_string(),
        );
        let mut v = serde_json::json!({
            "auth": {"accessToken": {"$wbEncrypted": 1, "envelope": env}}
        });
        let err = decrypt_json_in_place(&mut v, &dir).unwrap_err();
        assert!(
            err.contains("at-rest") || err.contains("密钥"),
            "err={err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
