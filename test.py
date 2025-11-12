# QwenWin32Renamer.py
# Требования:
# - Ollama запущен локально (http://localhost:11434)
# - Установлена модель: `ollama pull qwen2:7b` (или qwen2:1.5b для слабых ПК)
# - Ghidra ≥ 10.3

import json
import re
import requests
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.symbol import SourceType

# === Настройки ===
OLLAMA_URL = "http://localhost:11434/api/generate"
QWEN_MODEL = "qwen2:7b"  # или qwen2:1.5b, qwen2:0.5b
SKIP_FUNCTIONS = ["entry", "WinMain", "main", "_main", "DllMain", "start"]

def get_win32_api_calls(func):
    """Собирает имена вызываемых WinAPI из функции (по символам)"""
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
    """Собирает строки, на которые есть ссылки из функции"""
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
            print("❌ Ollama error:", response.text)
            return None
        return json.loads(response.text).get("response", "")
    except Exception as e:
        print("❌ Exception calling Ollama:", e)
        return None

def clean_json_from_markdown(text):
    """Извлекает JSON из markdown-блоков (если модель добавила ```json)"""
    match = re.search(r"```(?:json)?\s*({.*?})\s*```", text, re.DOTALL)
    if match:
        return match.group(1)
    return text.strip()

def apply_suggestions(func, suggestions):
    try:
        # 1. Имя функции
        if suggestions.get("function_name") and suggestions["function_name"] != func.getName():
            new_name = suggestions["function_name"]
            if new_name.replace("_", "").isalnum() and not new_name[0].isdigit():
                func.setName(new_name, SourceType.USER_DEFINED)
                print(f"✅ Renamed function to: {new_name}")

        # 2. Комментарий
        func_comment = suggestions.get("comments", {}).get("function")
        if func_comment:
            func.setComment(func_comment)
            print(f"💬 Set comment: {func_comment[:50]}...")

        # 3. Параметры и локальные переменные
        var_map = suggestions.get("variables", {})
        all_vars = list(func.getParameters()) + list(func.getLocalVariables())
        for var in all_vars:
            old_name = var.getName()
            if old_name in var_map and var_map[old_name] != old_name:
                new_var_name = var_map[old_name]
                if new_var_name.replace("_", "").isalnum() and not new_var_name[0].isdigit():
                    var.setName(new_var_name, SourceType.USER_DEFINED)
                    print(f"  ➕ Renamed var `{old_name}` → `{new_var_name}`")

    except Exception as e:
        print("⚠️ Error applying suggestions:", e)

def main():
    program = currentProgram
    decomp = DecompInterface()
    decomp.openProgram(program)

    funcs = [f for f in program.getFunctionManager().getFunctions(True)
             if not f.isThunk() and f.getSignature().getSource() != SourceType.IMPORT]

    print(f"🔍 Found {len(funcs)} functions. Processing...\n")

    for func in funcs:
        name = func.getName()
        if any(skip in name.lower() for skip in SKIP_FUNCTIONS):
            continue

        # Пропускаем слишком большие функции (защита от таймаута)
        if func.getBody().getNumAddresses() > 200:
            print(f"⏭ Skipping large function: {name}")
            continue

        print(f"\n🔧 Processing: {name}")

        # Получаем псевдокод
        res = decomp.decompileFunction(func, 60, ConsoleTaskMonitor())
        if not res.decompileCompleted():
            print("  ⚠️ Decompilation failed")
            continue
        code = res.getDecompiledFunction().getC()

        # Собираем контекст Win32
        apis = get_win32_api_calls(func)
        strs = get_referenced_strings(func)

        # Формируем промпт (на русском для Qwen — лучше понимает задачи RE)
        prompt = f"""Ты — эксперт по обратной разработке Windows-программ (Win32). 
Проанализируй следующую функцию и предложи:
1. Имя функции (camelCase или snake_case, на английском, без префиксов вроде 'sub_', 'FUN_').
2. Имена параметров и ключевых локальных переменных (только если текущие имена бессмысленные: param_1, iVar1 и т.п.).
3. Комментарий к функции в стиле Doxygen.

Контекст:
- Вызываемые WinAPI: {", ".join(apis) if apis else "нет"}
- Строковые константы: {", ".join(f'"{s}"' for s in strs) if strs else "нет"}

Декомпилированный код:
```c
{code}
