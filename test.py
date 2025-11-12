# QwenWin32Renamer_JavaNet.py
# Pure Jython-compatible Ghidra script (no 'requests')
# Uses java.net.URL for HTTP calls to Ollama

from java.net import URL, HttpURLConnection
from java.io import BufferedReader, InputStreamReader, OutputStreamWriter
import json
import re
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.symbol import SourceType

# === Settings ===
OLLAMA_URL = "http://localhost:11434/api/generate"
QWEN_MODEL = "qwen2:7b"
SKIP_FUNCTIONS = ["entry", "WinMain", "main", "_main", "DllMain", "start"]

def http_post_json(url_str, data_dict):
    """
    Sends POST request with JSON body.
    Returns (status_code, response_text) or (None, error_msg)
    """
    try:
        url = URL(url_str)
        conn = url.openConnection()
        conn.setRequestMethod("POST")
        conn.setDoOutput(True)
        conn.setRequestProperty("Content-Type", "application/json")
        conn.setRequestProperty("Accept", "application/json")
        conn.setConnectTimeout(10000)
        conn.setReadTimeout(120000)  # 2 min for LLM

        # Write JSON body
        writer = OutputStreamWriter(conn.getOutputStream(), "UTF-8")
        json_body = json.dumps(data_dict)
        writer.write(json_body)
        writer.flush()
        writer.close()

        status = conn.getResponseCode()
        # Read response (handle both success and error streams)
        stream = conn.getInputStream() if status == 200 else conn.getErrorStream()
        if stream is None:
            return status, ""

        reader = BufferedReader(InputStreamReader(stream, "UTF-8"))
        lines = []
        line = reader.readLine()
        while line is not None:
            lines.append(line)
            line = reader.readLine()
        reader.close()
        return status, "\n".join(lines)

    except Exception as e:
        return None, "Java HTTP Exception: " + str(e)

def ask_qwen(prompt):
    payload = {
        "model": QWEN_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.3}
    }

    status, resp_text = http_post_json(OLLAMA_URL, payload)
    if status != 200:
        print("Ollama error [{}]: {}".format(status, resp_text))
        return None

    try:
        data = json.loads(resp_text)
        return data.get("response", "")
    except Exception as e:
        print("JSON parse failed in response:", e)
        return None

def clean_json_from_markdown(text):
    match = re.search(r"```(?:json)?\s*({.*?})\s*```", text, re.DOTALL)
    if match:
        return match.group(1)
    return text.strip()

def get_win32_api_calls(func):
    api_calls = set()
    refs = func.getFunctionReferencesFrom()
    for ref in refs:
        to_func = ref.getToFunction()
        if to_func and not to_func.isExternal():
            continue
        sym = to_func.getSymbol() if to_func else None
        name = sym.getName() if sym else ref.getToAddress().toString()
        if name.startswith("KERNEL32::") or name.startswith("USER32::") or name.startswith("ADVAPI32::"):
            api_name = name.split("::")[-1]
            api_calls.add(api_name)
    return sorted(api_calls)

def get_referenced_strings(func):
    strings = set()
    listing = currentProgram.getListing()
    insns = listing.getInstructions(func.getBody(), True)
    for insn in insns:
        for op in insn.getOperandReferences():
            data = listing.getDataAt(op.getToAddress())
            if data and data.hasStringValue():
                s = data.getValue().toString()
                if 3 <= len(s) <= 64:
                    strings.add(s)
    return sorted(strings)

def apply_suggestions(func, suggestions):
    try:
        new_name = suggestions.get("function_name")
        if new_name and new_name != func.getName():
            clean_name = re.sub(r"[^a-zA-Z0-9_]", "_", new_name)
            if clean_name and clean_name[0].isalpha() and clean_name.replace("_", "").isalnum():
                func.setName(clean_name, SourceType.USER_DEFINED)
                print("Renamed function to:", clean_name)

        func_comment = suggestions.get("comments", {}).get("function")
        if func_comment:
            func.setComment(func_comment)
            print("Comment added:", func_comment[:60] + ("..." if len(func_comment) > 60 else ""))

        var_map = suggestions.get("variables", {})
        all_vars = list(func.getParameters()) + list(func.getLocalVariables())
        for var in all_vars:
            old_name = var.getName()
            if old_name in var_map:
                new_var = var_map[old_name]
                clean_var = re.sub(r"[^a-zA-Z0-9_]", "_", new_var)
                if clean_var and clean_var != old_name and clean_var[0].isalpha():
                    var.setName(clean_var, SourceType.USER_DEFINED)
                    print("  Var:", old_name, "->", clean_var)

    except Exception as e:
        print("Apply error:", e)

def main():
    program = currentProgram
    decomp = DecompInterface()
    decomp.openProgram(program)

    funcs = [f for f in program.getFunctionManager().getFunctions(True)
             if not f.isThunk() and f.getSignature().getSource() != SourceType.IMPORT]

    print("Found", len(funcs), "functions. Processing...")

    for func in funcs:
        name = func.getName()
        if any(skip in name.lower() for skip in SKIP_FUNCTIONS):
            continue
        if func.getBody().getNumAddresses() > 200:
            print("Skip large:", name)
            continue

        print("\n[+] Processing:", name)

        res = decomp.decompileFunction(func, 60, ConsoleTaskMonitor())
        if not res.decompileCompleted():
            print("  Decomp failed")
            continue
        code = res.getDecompiledFunction().getC()

        apis = get_win32_api_calls(func)
        strs = get_referenced_strings(func)

        prompt = (
            "You are a reverse engineering expert for Win32 binaries.\n"
            "Suggest a function name, variable names, and a comment.\n\n"
            "WinAPIs: " + (", ".join(apis) if apis else "none") + "\n"
            "Strings: " + (", ".join('"' + s + '"' for s in strs) if strs else "none") + "\n\n"
            "Code:\n```c\n" + code + "\n```\n\n"
            "Rules:\n"
            "- Output ONLY valid JSON.\n"
            "- ASCII names only.\n"
            "- If unsure, use 'unknown_action_XXXX'.\n"
            "Format:\n"
            "{"
            "\"function_name\":\"string\","
            "\"comments\":{\"function\":\"string or null\"},"
            "\"variables\":{\"old1\":\"new1\"}"
            "}"
        )

        resp = ask_qwen(prompt)
        if not resp:
            print("  No response from Ollama")
            continue

        try:
            json_str = clean_json_from_markdown(resp)
            suggestions = json.loads(json_str)
            fn = suggestions.get("function_name", "???")
            print("  -> Qwen:", fn)
            apply_suggestions(func, suggestions)
        except Exception as e:
            print("  JSON error:", e)

    print("\n[done] Check Ghidra changes.")

if __name__ == "__main__":
    main()
