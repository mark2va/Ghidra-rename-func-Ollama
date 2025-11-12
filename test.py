# QwenWin32Renamer_ASCII.py
# Requirements:
# - Ollama running (http://localhost:11434)
# - Model installed: `ollama pull qwen2:7b` (or qwen2:1.5b / 0.5b)
# - Ghidra >= 10.3

import json
import re
import requests
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.symbol import SourceType

# === Settings ===
OLLAMA_URL = "http://localhost:11434/api/generate"
QWEN_MODEL = "qwen2:7b"
SKIP_FUNCTIONS = ["entry", "WinMain", "main", "_main", "DllMain", "start"]

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
                if len(s) >= 3 and len(s) <= 64:
                    strings.add(s)
    return sorted(strings)

def ask_qwen(prompt):
    try:
        response = requests.post(
            OLLAMA_URL,
            json={
                "model": QWEN_MODEL,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.3}
            },
            timeout=120
        )
        if response.status_code != 200:
            print("ERROR: Ollama returned status", response.status_code)
            return None
        return json.loads(response.text).get("response", "")
    except Exception as e:
        print("EXCEPTION calling Ollama:", e)
        return None

def clean_json_from_markdown(text):
    match = re.search(r"```(?:json)?\s*({.*?})\s*```", text, re.DOTALL)
    if match:
        return match.group(1)
    return text.strip()

def apply_suggestions(func, suggestions):
    try:
        new_name = suggestions.get("function_name")
        if new_name and new_name != func.getName():
            if new_name.replace("_", "").isalnum() and not new_name[0].isdigit():
                func.setName(new_name, SourceType.USER_DEFINED)
                print("Renamed function to:", new_name)

        func_comment = suggestions.get("comments", {}).get("function")
        if func_comment:
            func.setComment(func_comment)
            print("Added comment:", func_comment[:50] + ("..." if len(func_comment) > 50 else ""))

        var_map = suggestions.get("variables", {})
        all_vars = list(func.getParameters()) + list(func.getLocalVariables())
        for var in all_vars:
            old_name = var.getName()
            if old_name in var_map:
                new_var_name = var_map[old_name]
                if new_var_name != old_name and new_var_name.replace("_", "").isalnum() and not new_var_name[0].isdigit():
                    var.setName(new_var_name, SourceType.USER_DEFINED)
                    print("  Renamed variable:", old_name, "->", new_var_name)

    except Exception as e:
        print("WARNING: Failed to apply suggestions:", e)

def main():
    program = currentProgram
    decomp = DecompInterface()
    decomp.openProgram(program)

    funcs = [f for f in program.getFunctionManager().getFunctions(True)
             if not f.isThunk() and f.getSignature().getSource() != SourceType.IMPORT]

    print("Found", len(funcs), "functions. Processing...\n")

    for func in funcs:
        name = func.getName()
        if any(skip in name.lower() for skip in SKIP_FUNCTIONS):
            continue
        if func.getBody().getNumAddresses() > 200:
            print("Skipping large function:", name)
            continue

        print("\nProcessing:", name)

        res = decomp.decompileFunction(func, 60, ConsoleTaskMonitor())
        if not res.decompileCompleted():
            print("  Decompilation failed")
            continue
        code = res.getDecompiledFunction().getC()

        apis = get_win32_api_calls(func)
        strs = get_referenced_strings(func)

        prompt = f"""You are a reverse engineering expert specializing in Win32 binaries.
Analyze the following function and suggest:
1. A meaningful function name (camelCase or snake_case, English only, no 'sub_', 'FUN_', etc.).
2. Names for parameters/local variables if current names are generic (e.g., param_1, iVar1).
3. A Doxygen-style comment for the function.

Context:
- Called WinAPIs: {', '.join(apis) if apis else 'none'}
- Referenced strings: {', '.join(f'"{s}"' for s in strs) if strs else 'none'}

Decompiled code:
```c
{code}
