# -*- coding: utf-8 -*-
# RenameAllFunctionsImproved.py
# Ghidra script (Jython 2.7) - compatible with Ghidra 9.2 - 11.x
#
# Purpose: improve program understanding by renaming functions with a local
# LLM (Ollama or LM Studio). Rules:
#   1. EMPTY functions (no body / only return) are SKIPPED.
#   2. Functions that merely call another function (a simple wrapper/thunk,
#      possibly with argument preparation) are SKIPPED - their meaning is
#      already conveyed by the callee on the call graph.
#   3. Functions containing potentially MALICIOUS behaviour are marked with
#      the "MLW_" prefix (MaLoWe) and renamed according to their logic.
#   4. All other functions are renamed based on their CONTROL FLOW analysis
#      (loops, branches, calls in order), so the Call Graph shows meaningful
#      names and it is obvious what each function does further down the graph.
#
# Usage: copy this file into %user%/ghidra_scripts, start a local LLM server -
#        Ollama  ("ollama serve", default port 11434)  OR
#        LM Studio (Developer tab -> "Start Server", default port 1234)
#        then run the script from Ghidra:
#        Window -> Script Manager -> ReNameAllFuncImproved.py
#        The server type, port and model are detected AUTOMATICALLY from the
#        IP address you set in LLM_HOST below.
#
# For better results place THIS script next to ReNameFunc.py (single-function
# renamer): rename the most interesting/complex functions first via
# ReNameFunc.py, then run this batch script - already-named callees will be
# used as context and skipped (their symbol source becomes USER_DEFINED).

import json
import re

from java.net import URL
from java.io import BufferedReader, InputStreamReader, OutputStreamWriter

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.symbol import SourceType

# =============================== Settings ==================================
# --- The ONLY thing you normally need to set is the IP address of the box
#     running your local LLM server ("127.0.0.1" if it runs on this PC).
#     Supported servers are detected automatically: Ollama AND LM Studio.
LLM_HOST = "127.0.0.1"

# Ports scanned automatically (Ollama default 11434, LM Studio default 1234).
# You can add custom ports here, e.g. 11435 (second ollama instance),
# 8080 / 5000 (LM Studio user-configured ports).
LLM_PORTS = [11434, 1234, 8080]

LLM_TIMEOUT = 15                 # network timeout for detection requests, sec
LLM_PREFER_MODEL = ""            # optional mask of the wanted model,
                                 # e.g. "qwen2.5-coder" (substring match)
LLM_AUTO_DETECT = True           # False -> use LLM_MODEL below as-is
LLM_MODEL = ""                   # explicit model name (used when auto-detect
                                 # is off, or as fallback if detection fails)
TEMPERATURE = 0.2

# Filled in by detect_llm_server() at runtime - do not edit manually.
LLM_BASE_URL = ""                # e.g. "http://127.0.0.1:1234"
LLM_KIND = ""                    # "ollama" | "lmstudio"
CHAT_PATH = "/v1/chat/completions"   # OpenAI-compatible (LM Studio + Ollama)
GEN_PATH = "/api/generate"           # native Ollama completion endpoint
TAGS_PATH = "/api/tags"              # native Ollama model list
MODELS_PATH = "/v1/models"           # OpenAI-compatible model list

MLW_PREFIX = "MLW_"                # marker for potentially malicious functions
MAX_BODY_BYTES = 65536             # skip huge functions (LLM prompt limit)
DECOMPILE_TIMEOUT = 60             # seconds per function

# Win32/CRT APIs typical for malware behaviour -> used for MLW heuristics
MALICIOUS_APIS = set([
    # process injection / creation
    "VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory", "ReadProcessMemory",
    "CreateRemoteThread", "CreateRemoteThreadEx", "NtCreateThreadEx",
    "RtlCreateUserThread", "QueueUserAPC", "SetThreadContext", "GetThreadContext",
    "OpenProcess", "OpenThread", "NtUnmapViewOfSection", "Wow64SetThreadContext",
    "CreateProcessA", "CreateProcessW", "CreateProcessAsUserA", "CreateProcessAsUserW",
    "ShellExecuteA", "ShellExecuteW", "WinExec",
    # dynamic loading / obfuscation
    "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
    "GetProcAddress", "LdrLoadDll", "LdrGetProcedureAddress", "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "OutputDebugStringA",
    # persistence
    "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW",
    "RegDeleteValueA", "RegDeleteValueW", "URLDownloadToFileA", "URLDownloadToFileW",
    "WinHttpOpen", "WinHttpConnect", "WinHttpOpenRequest", "WinHttpSendRequest",
    "WinHttpReceiveResponse", "InternetOpenA", "InternetConnectA", "HttpSendRequestA",
    "WSAStartup", "socket", "connect", "send", "recv", "closesocket",
    # file / data theft
    "CreateFileA", "CreateFileW", "DeleteFileA", "DeleteFileW", "MoveFileA",
    "FindFirstFileA", "FindNextFileA", "CryptEncrypt", "CryptDecrypt",
    "GetUserNameA", "GetComputerNameA", "GetVersionExA", "DeviceIoControl",
    "SetWindowsHookExA", "SetWindowsHookExW", "keybd_event", "GetAsyncKeyState",
    "EnumProcesses", "CreateServiceA", "CreateServiceW", "StartServiceA",
    "schtasks", "vssadmin",
])

# Suspicious strings (encryption ransomware notes, dropped paths etc.)
SUSPICIOUS_STRING_RX = re.compile(
    r"(recover|decrypt|bitcoin|base64\.onion|aes-|xor key|"
    r"cmd\s*/c|powershell|-enc |mimikatz|lsass|"
    r"%APPDATA%|%TEMP%|%LOCALAPPDATA%|\\\\\.\\PIPE|"
    r"Software\\Microsoft\\Windows\\CurrentVersion\\Run)",
    re.IGNORECASE)


# ============================ HTTP / LLM layer =============================
def http_get_json(url_str):
    """GET a JSON document; returns (http_code, parsed_dict or None)."""
    try:
        url = URL(url_str)
        conn = url.openConnection()
        conn.setConnectTimeout(LLM_TIMEOUT * 1000)
        conn.setReadTimeout(LLM_TIMEOUT * 1000)
        conn.setRequestMethod("GET")
        code = conn.getResponseCode()
        if code != 200:
            return code, None
        reader = BufferedReader(InputStreamReader(conn.getInputStream(), "UTF-8"))
        body = []
        line = reader.readLine()
        while line is not None:
            body.append(line)
            line = reader.readLine()
        reader.close()
        return code, json.loads("\n".join(body))
    except Exception as e:
        return -1, None


def http_post_json(url_str, data_dict, read_timeout_ms=None):
    try:
        url = URL(url_str)
        conn = url.openConnection()
        conn.setConnectTimeout(LLM_TIMEOUT * 1000)
        conn.setReadTimeout(read_timeout_ms or 300000)  # generation may be slow
        conn.setDoOutput(True)
        conn.setRequestProperty("Content-Type", "application/json")

        writer = OutputStreamWriter(conn.getOutputStream(), "UTF-8")
        writer.write(json.dumps(data_dict))
        writer.flush()
        writer.close()

        code = conn.getResponseCode()
        stream = conn.getInputStream() if code == 200 else conn.getErrorStream()
        if not stream:
            return code, ""
        reader = BufferedReader(InputStreamReader(stream, "UTF-8"))
        body = []
        line = reader.readLine()
        while line is not None:
            body.append(line)
            line = reader.readLine()
        reader.close()
        return code, "\n".join(body)
    except Exception as e:
        return -1, "Exception: " + str(e)


def _model_id(entry):
    """Extract a usable model id from an Ollama/LM Studio model entry."""
    if isinstance(entry, dict):
        return entry.get("name") or entry.get("id") or ""
    return str(entry)


def list_models(base_url, kind):
    """Return the list of model ids available on the detected server."""
    models = []
    if kind == "ollama":
        code, data = http_get_json(base_url + TAGS_PATH)
        if data and "models" in data:
            models = [_model_id(m) for m in data["models"]]
    else:  # lmstudio (OpenAI-compatible)
        code, data = http_get_json(base_url + MODELS_PATH)
        if data and "data" in data:
            models = [_model_id(m) for m in data["data"]]
    return [m for m in models if m]


def pick_model(models):
    """Choose the best model automatically: prefer mask -> coder keywords ->
    any coding-ish model -> first available."""
    if not models:
        return None
    low = dict((m.lower(), m) for m in models)

    if LLM_PREFER_MODEL:
        mask = LLM_PREFER_MODEL.lower()
        for k in sorted(low):
            if mask in k:
                return low[k]

    priority = ["coder", "codegemma", "starcoder", "code llama", "codellama",
                "deepseek-coder", "phi", "qwen", "gemma", "llama", "mistral"]
    for kw in priority:
        for k in sorted(low):
            if kw in k:
                return low[k]
    return models[0]


def probe_server(host, port):
    """Identify what runs on host:port. Returns (kind, base_url) or (None, None).
    Ollama answers GET /api/tags, LM Studio answers GET /v1/models."""
    base = "http://%s:%d" % (host, port)
    code, data = http_get_json(base + TAGS_PATH)
    if code == 200 and isinstance(data, dict) and "models" in data:
        return "ollama", base
    code, data = http_get_json(base + MODELS_PATH)
    if code == 200 and isinstance(data, dict) and "data" in data:
        return "lmstudio", base
    return None, None


def detect_llm_server():
    """Auto-detect server type (Ollama / LM Studio), port and model.
    Only LLM_HOST must be provided by the user. Returns True on success."""
    global LLM_BASE_URL, LLM_KIND, LLM_MODEL

    if not LLM_AUTO_DETECT:
        LLM_BASE_URL = "http://%s:%d" % (LLM_HOST, LLM_PORTS[0])
        LLM_KIND = "ollama"
        print("[DETECT] auto-detect disabled, using %s, model=%s"
              % (LLM_BASE_URL, LLM_MODEL))
        return bool(LLM_MODEL)

    print("[DETECT] scanning %s on ports %s for Ollama / LM Studio ..."
          % (LLM_HOST, ", ".join(str(p) for p in LLM_PORTS)))
    for port in LLM_PORTS:
        kind, base = probe_server(LLM_HOST, port)
        if kind is None:
            continue
        models = list_models(base, kind)
        chosen = pick_model(models)
        if chosen is None:
            print("[DETECT] port %d: %s server found but has NO models loaded."
                  % (port, kind))
            if kind == "lmstudio":
                print("[DETECT] load a model in the LM Studio UI (it must be "
                      "served via Developer -> Start Server) and retry.")
            continue
        LLM_BASE_URL, LLM_KIND, LLM_MODEL = base, kind, chosen
        print("[DETECT] FOUND %-9s at %s | model: %s | available: %d"
              % (kind.upper(), base, chosen, len(models)))
        warmup_llm()
        return True

    print("[DETECT] ERROR: no supported LLM server found on %s (ports %s)."
          % (LLM_HOST, ", ".join(str(p) for p in LLM_PORTS)))
    print("         Check that Ollama ('ollama serve', port 11434) or")
    print("         LM Studio (Developer -> Start Server, port 1234) is running,")
    print("         that CORS/remote access is enabled, and/or extend LLM_PORTS.")
    return False


def warmup_llm():
    """Tiny request to make sure the model is loaded and answering."""
    resp = ask_llm("Reply with the single word: OK")
    if resp is None:
        print("[DETECT] WARNING: warm-up request failed, continuing anyway.")
    else:
        print("[DETECT] warm-up OK (%s answered)." % LLM_KIND)


def ask_llm(prompt):
    """Send a prompt to the detected server (Ollama native or LM Studio
    OpenAI-compatible chat API). Returns the text answer or None."""
    system = ("You are a reverse engineering expert. Always answer with valid "
              "JSON only, no extra prose.")
    if LLM_KIND == "lmstudio":
        payload = {
            "model": LLM_MODEL,
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": prompt}],
            "temperature": TEMPERATURE,
            "max_tokens": 512,
            "stream": False,
        }
        status, text = http_post_json(LLM_BASE_URL + CHAT_PATH, payload)
        if status != 200:
            print("LM Studio error [%s]: %s" % (status, text[:200]))
            return None
        try:
            return json.loads(text)["choices"][0]["message"]["content"]
        except Exception:
            print("Bad response from LM Studio")
            return None

    # ---- Ollama: native /api/generate gives cleaner raw completion
    payload = {
        "model": LLM_MODEL,
        "prompt": prompt,
        "system": system,
        "stream": False,
        "options": {"temperature": TEMPERATURE},
    }
    status, text = http_post_json(LLM_BASE_URL + GEN_PATH, payload)
    if status != 200:
        print("Ollama error [%s]: %s" % (status, text[:200]))
        return None
    try:
        return json.loads(text).get("response", "")
    except Exception:
        print("Bad JSON from Ollama")
        return None


def extract_json(text):
    """Pull the first {...} block out of an LLM answer (handles ```json fences)."""
    if not text:
        return None
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    candidate = m.group(1) if m else None
    if candidate is None:
        try:
            start = text.index('{')
            end = text.rindex('}') + 1
            candidate = text[start:end]
        except ValueError:
            return None
    try:
        return json.loads(candidate)
    except Exception:
        return None


def safe_name(name):
    n = re.sub(r"[^a-zA-Z0-9_]", "_", str(name)).strip("_")
    if not n or not ("a" <= n[0].lower() <= "z"):
        n = "fun_" + n
    return n[:60]


# ========================= Static analysis helpers =========================
def decompile(decomp, func, monitor):
    try:
        res = decomp.decompileFunction(func, DECOMPILE_TIMEOUT, monitor)
        if res is None or not res.decompileCompleted():
            return None
        df = res.getDecompiledFunction()
        if df is None:
            return None
        return df.getC()
    except Exception:
        return None


def get_called_functions(func):
    """All functions called from this function (internal + external)."""
    result = []
    seen = set()
    try:
        refs = func.getFunctionReferencesFrom()
    except Exception:
        refs = []
    for ref in refs:
        rt = ref.getReferenceType()
        if rt.isCall():
            to_addr = ref.getToAddress()
            to_func = currentProgram.getFunctionManager().getFunctionAt(to_addr)
            if to_func is None:
                to_func = currentProgram.getFunctionManager().getFunctionContaining(to_addr)
            if to_func is not None:
                key = to_func.getEntryPoint()
                if key not in seen:
                    seen.add(key)
                    result.append(to_func)
    return result


def get_external_api_names(func):
    apis = set()
    for callee in get_called_functions(func):
        if callee.isExternal() or callee.isThunk():
            name = callee.getName()
            if "::" in name:
                name = name.split("::")[-1]
            apis.add(name)
    return apis


def get_strings_in_func(func):
    strs = set()
    listing = currentProgram.getListing()
    try:
        insns = listing.getInstructions(func.getBody(), True)
    except Exception:
        return strs
    for insn in insns:
        try:
            refs = insn.getReferences()
        except Exception:
            continue
        for ref in refs:
            data = listing.getDataAt(ref.getToAddress())
            if data is not None and data.hasStringValue():
                try:
                    s = data.getValue().toString()
                except Exception:
                    continue
                if 3 <= len(s) <= 128 and all(ord(c) < 127 for c in s):
                    strs.add(s)
    return strs


NON_CODE_TOKEN_RX = re.compile(
    r"^(//|/\*|\}?\s*else\b|\}|\{|case |default:|break;|continue;)")


def is_empty_code(code):
    """True if the decompiled body has no real work (empty / only return)."""
    if not code:
        return True
    m = re.search(r"\{(.*)\}", code, re.DOTALL)
    body = m.group(1) if m else code
    for raw in body.splitlines():
        line = raw.strip()
        if not line or NON_CODE_TOKEN_RX.match(line):
            continue
        # "return;" / "return 0;" / "return iVar;" - no real work
        if re.match(r"^return(;|[^;]*;)$", line):
            continue
        # anything else that performs a call/assignment/operation is real work
        return False
    return True


def count_code_lines(code):
    """Approximate number of real statements in decompiled C."""
    if not code:
        return 0
    body = code
    m = re.search(r"\{(.*)\}", code, re.DOTALL)
    if m:
        body = m.group(1)
    lines = 0
    for raw in body.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("//") or line.startswith("/*"):
            continue
        if line in ("{", "}"):
            continue
        lines += 1
    return lines


CFG_CALL_RX = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", re.MULTILINE)

NON_CALLEE_TOKENS = set([
    "if", "for", "while", "switch", "return", "sizeof", "do", "else",
    "case", "break", "continue", "goto", "int", "uint", "char", "void",
    "long", "short", "float", "double", "unsigned", "signed", "struct",
    "undefined1", "undefined2", "undefined4", "undefined8",
    "DAT", "PTR", "uVar", "iVar", "local", "CONCAT", "ZEXT", "SEXT",
])


def build_control_flow_summary(code, func):
    """
    Produce a compact control-flow skeleton of the function:
      - decision points (if/while/for/switch) with their conditions
      - calls in execution order
      - gotos / loops
    This lets the LLM rename according to the LOGIC, not just API names.
    """
    if not code:
        return ""
    m = re.search(r"\{(.*)\}", code, re.DOTALL)
    body = m.group(1) if m else code

    summary = []
    depth = 0
    for raw in body.splitlines():
        line = raw.strip()
        if not line:
            continue
        low = line.lower()
        indent = "  " * depth
        if low.startswith(("if ", "if(", "while ", "while(", "for ", "for(",
                           "switch ", "switch(", "} else", "else if",
                           "else {", "else", "case ", "default:", "goto ")):
            summary.append(indent + line[:160])
        elif "(" in line and ";" in line:
            calls = [c for c in CFG_CALL_RX.findall(line)
                     if c not in NON_CALLEE_TOKENS]
            if calls:
                summary.append(indent + "-> " + ", ".join(calls) + ";")
        # track brace depth roughly
        depth += line.count("{") - line.count("}")
        if depth < 0:
            depth = 0

    callees = get_called_functions(func)
    if callees:
        names = []
        for c in callees:
            tag = "EXTERNAL" if (c.isExternal() or c.isThunk()) else "internal"
            names.append("%s (%s)" % (c.getName(), tag))
        summary.append("CALLEES: " + ", ".join(names))

    return "\n".join(summary[:120])


def classify_function(func, code):
    """
    Decide what to do with the function. Returns one of:
      ("skip_empty", reason)
      ("skip_wrapper", reason)
      ("rename_mlw", reason)          - malicious -> MLW_ prefix
      ("rename_ml", reason)           - normal -> rename by logic
    """
    # ---- THUNK / PLT stub -> pure wrapper
    if func.isThunk():
        return ("skip_wrapper", "thunk/stub (single jump to another function)")

    body = func.getBody()
    num_addresses = body.getNumAddresses() if body is not None else 0

    # ---- EMPTY function (no body / only return)
    if is_empty_code(code):
        listing = currentProgram.getListing()
        try:
            insns = list(listing.getInstructions(body, True)) \
                if body is not None else []
        except Exception:
            insns = []
        meaningful = [i for i in insns
                      if str(i.getMnemonic()).lower()
                      not in ("return", "ret", "halt", "nop")]
        if num_addresses <= 2 or len(meaningful) == 0:
            return ("skip_empty", "empty function (no code / only return)")

    # ---- Wrapper: body consists of a single call (optionally with arg setup)
    callees = get_called_functions(func)
    code_lines = count_code_lines(code)
    if len(callees) == 1:
        callee = callees[0]
        # single call + return, no loops/branches of substance
        has_branching = code is not None and re.search(
            r"\b(if|for|while|switch|goto)\b", code) is not None
        if not has_branching and code_lines <= 4:
            if callee.getName() != func.getName():  # not recursive
                return ("skip_wrapper",
                        "wrapper around %s()" % callee.getName())

    # ---- Malicious heuristics
    apis = get_external_api_names(func)
    hit_apis = sorted(apis & MALICIOUS_APIS)
    reasons = []
    score = 0
    if hit_apis:
        score += len(hit_apis)
        reasons.append("APIs: " + ", ".join(hit_apis))
    strs = get_strings_in_func(func)
    hit_strs = [s for s in strs if SUSPICIOUS_STRING_RX.search(s)]
    if hit_strs:
        score += 2 * len(hit_strs)
        reasons.append("strings: " + ", ".join(hit_strs[:3]))
    # classic injection combo
    api_set = set(hit_apis)
    injection_combo = (("VirtualAlloc" in api_set or "VirtualAllocEx" in api_set)
                       and "CreateRemoteThread" in api_set)
    dyn_resolve = ("GetProcAddress" in api_set
                   and ("LoadLibraryA" in api_set or "LoadLibraryW" in api_set))
    if injection_combo:
        score += 5
        reasons.append("process-injection pattern")
    if dyn_resolve:
        score += 2
        reasons.append("dynamic API resolution")
    # many suspicious Win32 handles opened on other processes
    if "OpenProcess" in api_set and ("ReadProcessMemory" in api_set
                                     or "WriteProcessMemory" in api_set):
        score += 3
        reasons.append("cross-process memory access")

    if score >= 2:
        return ("rename_mlw", "; ".join(reasons))

    return ("rename_ml", "normal logic function")


# ============================ Renaming layer ===============================
def llm_suggest_name(func, code, flow, kind, reason):
    mlw_hint = ""
    if kind == "rename_mlw":
        mlw_hint = (
            "IMPORTANT: this function shows potentially MALICIOUS behaviour "
            "(%s). The new name MUST start with \"MLW_\" followed by a short "
            "description of WHAT IT DOES (e.g. MLW_InjectCodeIntoRemoteProcess)."
            % reason)
    else:
        mlw_hint = (
            "The name must reflect the CONTROL FLOW and purpose of the "
            "function (what it checks, loops over, calls, returns), so that "
            "the call graph is easy to read.")

    prompt = (
        "You are a reverse engineering expert improving program understanding.\n"
        "Analyse the function below and return ONLY a JSON object:\n"
        "{\"function_name\": \"DescriptiveName\", \"reason\": \"one sentence\"}\n\n"
        "Rules:\n"
        "- ASCII letters/digits/underscore only, CamelCase, max 50 chars.\n"
        "- No \"func_\", \"FUN_\", \"thunk_\" prefixes.\n"
        "- " + mlw_hint + "\n\n"
        "Static analysis hints (%s):\n%s\n\n"
        "Control flow skeleton:\n%s\n\n"
        "Decompiled C code:\n```c\n%s\n```\n"
        % (kind, reason, flow if flow else "(none)", code)
    )

    resp = ask_llm(prompt)
    data = extract_json(resp)
    if data and isinstance(data, dict) and "function_name" in data:
        return safe_name(data["function_name"]), data.get("reason", "")
    return None, None


def apply_new_name(func, new_name, kind):
    if kind == "rename_mlw" and not new_name.startswith(MLW_PREFIX):
        new_name = MLW_PREFIX + new_name
    old = func.getName()
    if new_name == old:
        print("   name unchanged: %s" % old)
        return
    try:
        func.setName(new_name, SourceType.USER_DEFINED)
        print("   RENAMED: %s -> %s%s"
              % (old, new_name, "  [MLW]" if kind == "rename_mlw" else ""))
    except Exception as e:
        print("   rename failed: %s" % e)


def add_mlwl_marker_comment(func, reason):
    try:
        func.setComment("[MLW] Potentially malicious: " + reason)
    except Exception:
        pass


# ================================ Main =====================================

def _is_library_source(src):
    """
    Return True if the function SourceType marks a library/shared-library
    function. Different Ghidra versions expose different enum names, and
    'LIBRARY_FUNCTION' does NOT exist (using it raises AttributeError), so
    we resolve constants dynamically:
      - LIBRARY          (exists in all recent Ghidra versions)
      - SHARED_LIBRARY   (older Ghidra versions)
    Comparison is done by both identity and name for maximum robustness.
    """
    lib_names = ("LIBRARY", "SHARED_LIBRARY")
    for attr in lib_names:
        const = getattr(SourceType, attr, None)
        if const is not None and src == const:
            return True
    try:
        if str(src) in lib_names:
            return True
    except Exception:
        pass
    return False


def main():
    print("=" * 60)
    print("LLM function renamer (control-flow aware, MLW marking)")
    print("=" * 60)

    # ---- Automatic server detection: only LLM_HOST is required.
    # Finds Ollama or LM Studio, picks the port and chooses a model.
    if not detect_llm_server():
        print("Aborted: no usable local LLM server (Ollama / LM Studio) found.")
        return
    print("Server: %s | %s | Model: %s"
          % (LLM_KIND.upper(), LLM_BASE_URL, LLM_MODEL))
    print("=" * 60)

    prog = currentProgram
    fm = prog.getFunctionManager()

    decomp = DecompInterface()
    decomp.openProgram(prog)
    monitor = ConsoleTaskMonitor()

    stats = {"total": 0, "skipped_empty": 0, "skipped_wrapper": 0,
             "renamed": 0, "renamed_mlw": 0, "errors": 0}

    funcs = list(fm.getFunctions(True))
    pending = []           # functions that still need an LLM suggestion
    analyzed_names = set() # names already analysed in THIS run (no duplicates)

    for func in funcs:
        stats["total"] += 1

        # external/library functions are not part of the binary itself
        if func.isExternal():
            continue
        src = func.getSymbol().getSource()
        # NOTE: ghidra.program.model.symbol.SourceType has NO attribute named
        # LIBRARY_FUNCTION (that was the AttributeError). The constant that
        # marks functions coming from shared libraries / library image is
        # SourceType.LIBRARY. We resolve it defensively so the script works
        # on every Ghidra version regardless of enum naming changes.
        if _is_library_source(src):
            continue
        # already renamed by the analyst (e.g. via ReNameFunc.py or a previous
        # pass of this script) -> skip; its meaningful name is on the graph
        if src == SourceType.USER_DEFINED:
            continue

        name = func.getName()
        if name in analyzed_names:
            continue
        analyzed_names.add(name)

        body = func.getBody()
        if body is not None and body.getNumAddresses() > MAX_BODY_BYTES:
            print("[SKIP BIG] %s (too large for analysis)" % name)
            continue

        code = decompile(decomp, func, monitor)
        kind, reason = classify_function(func, code)

        if kind == "skip_empty":
            stats["skipped_empty"] += 1
            print("[SKIP EMPTY]    %-30s %s" % (name, reason))
            continue

        if kind == "skip_wrapper":
            stats["skipped_wrapper"] += 1
            print("[SKIP WRAPPER]  %-30s %s" % (name, reason))
            continue

        flow = build_control_flow_summary(code, func)
        pending.append((func, code, flow, kind, reason))

    # Second pass: ask the LLM only for real logic functions. Renaming here
    # updates func.getName(), so the printed log always shows the final state.
    for func, code, flow, kind, reason in pending:
        new_name, why = llm_suggest_name(func, code, flow, kind, reason)

        if new_name is None:
            stats["errors"] += 1
            print("[NO SUGGESTION] %-30s (%s)" % (func.getName(), reason))
            continue

        apply_new_name(func, new_name, kind)
        analyzed_names.add(new_name)
        if kind == "rename_mlw":
            add_mlwl_marker_comment(func, reason)
            stats["renamed_mlw"] += 1
            print("[MLW]  %-30s reason: %s | model: %s"
                  % (new_name, reason, why))
        else:
            stats["renamed"] += 1
            print("[OK]   %-30s reason: %s" % (new_name, why))

    print("=" * 60)
    print("Done. total=%d  renamed=%d  renamed_MLW=%d  "
          "skipped_empty=%d  skipped_wrapper=%d  errors=%d"
          % (stats["total"], stats["renamed"], stats["renamed_mlw"],
             stats["skipped_empty"], stats["skipped_wrapper"], stats["errors"]))
    print("Tip: open Window -> Call Graph or Symbol Tree; MLW_ functions are")
    print("     easy to spot and their callees show the next steps.")


main()
