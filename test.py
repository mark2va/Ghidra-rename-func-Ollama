# QwenWin32Renamer_Compat.py
# Compatible with Ghidra 9.2 - 10.3+
# No 'requests', no .getSource(), no non-ASCII chars

from java.net import URL
from java.io import BufferedReader, InputStreamReader, OutputStreamWriter
import json
import re
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.symbol import SourceType

OLLAMA_URL = "http://localhost:11434/api/generate"
QWEN_MODEL = "qwen2:7b"
SKIP_FUNCTIONS = ["entry", "WinMain", "main", "_main", "DllMain", "start"]

def http_post_json(url_str, data_dict):
    try:
        url = URL(url_str)
        conn = url.openConnection()
        conn.setDoOutput(True)
        conn.setRequestProperty("Content-Type", "application/json")
        # HttpURLConnection cast for setRequestMethod (required in Java)
        conn = conn  # In Jython, often works without explicit cast
        # Note: setRequestMethod may not be available on older Ghidra/JVM
        # We rely on default POST via setDoOutput + getOutputStream
        out = conn.getOutputStream()
        writer = OutputStreamWriter(out, "UTF-8")
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

def ask_qwen(prompt):
    payload = {
        "model": QWEN_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.3}
    }
    status, text = http_post_json(OLLAMA_URL, payload)
    if status != 200:
        print("Ollama error [{}]: {}".format(status, text[:200]))
        return None
    try:
        return json.loads(text).get("response", "")
    except:
        print("Bad JSON from Ollama")
        return None

def clean_json(s):
    m = re.search(r"```(?:json)?\s*({.*?})\s*```", s, re.DOTALL)
    return m.group(1) if m else s.strip()

def get_api_calls(func):
    apis = set()
    for ref in func.getFunctionReferencesFrom():
        to_func = ref.getToFunction()
        if to_func and to_func.isExternal():
            sym = to_func.getSymbol()
            name = sym.getName()
            if "::" in name:
                name = name.split("::")[-1]
            apis.add(name)
    return sorted(apis)

def get_strings(func):
    strs = set()
    listing = currentProgram.getListing()
    for insn in listing.getInstructions(func.getBody(), True):
        for ref in insn.getOperandReferences():
            data = listing.getDataAt(ref.getToAddress())
            if data and data.hasStringValue():
                s = data.getValue().toString()
                if 3 <= len(s) <= 64 and all(ord(c) < 127 for c in s):
                    strs.add(s)
    return sorted(strs)

def safe_name(name):
    n = re.sub(r"[^a-zA-Z0-9_]", "_", name)
    if not n or not n[0].isalpha():
        return "var_" + n
    return n

def apply_sug(func, sug):
    try:
        fn = sug.get("function_name")
        if fn and fn != func.getName():
            func.setName(safe_name(fn), SourceType.USER_DEFINED)
            print("->", fn)

        comm = sug.get("comments", {}).get("function")
        if comm:
            func.setComment(comm)

        var_map = sug.get("variables", {})
        for var in list(func.getParameters()) + list(func.getLocalVariables()):
            old = var.getName()
            if old in var_map:
                new = var_map[old]
                if new and new != old:
                    var.setName(safe_name(new), SourceType.USER_DEFINED)
    except Exception as e:
        print("Apply error:", e)

def main():
    prog = currentProgram
    decomp = DecompInterface()
    decomp.openProgram(prog)

    # ✅ Fix: use isExternal() instead of getSignature().getSource()
    funcs = [f for f in prog.getFunctionManager().getFunctions(True)
             if not f.isThunk() and not f.isExternal()]

    print("Functions to process:", len(funcs))

    for f in funcs:
        name = f.getName()
        if any(k in name.lower() for k in SKIP_FUNCTIONS):
            continue
        if f.getBody().getNumAddresses() > 200:
            continue

        print("\n[+] ", name)

        res = decomp.decompileFunction(f, 60, ConsoleTaskMonitor())
        if not res.decompileCompleted():
            continue
        code = res.getDecompiledFunction().getC()

        apis = get_api_calls(f)
        strs = get_strings(f)

        prompt = (
            "You are a Win32 reverse engineer. Suggest JSON:\n"
            "WinAPI: " + (", ".join(apis) if apis else "none") + "\n"
            "Strings: " + (", ".join('"' + s + '"' for s in strs) if strs else "none") + "\n"
            "Code:\n```c\n" + code + "\n```\n"
            "Rules: ASCII names only. Output ONLY JSON:\n"
            '{"function_name":"str","comments":{"function":"str"},"variables":{"old":"new"}}'
        )

        resp = ask_qwen(prompt)
        if not resp:
            continue

        try:
            sug = json.loads(clean_json(resp))
            apply_sug(f, sug)
        except Exception as e:
            pass  # silent fail to keep batch going

    print("\nDone.")

if __name__ == "__main__":
    main()
