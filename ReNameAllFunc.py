# -*- coding: utf-8 -*-
#OllamaRenameAllFunctions.py
import json
import re
from java.net import URL
from java.io import BufferedReader, InputStreamReader, OutputStreamWriter
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.symbol import SourceType

# Settings
OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "codellama"

def send_to_ollama(prompt):
    try:
        url = URL(OLLAMA_URL)
        conn = url.openConnection()
        conn.setDoOutput(True)
        conn.setRequestProperty("Content-Type", "application/json")

        output = OutputStreamWriter(conn.getOutputStream())
        data = json.dumps({
            "model": MODEL_NAME,
            "prompt": prompt,
            "stream": False
        })
        output.write(data)
        output.flush()
        output.close()

        input_stream = BufferedReader(InputStreamReader(conn.getInputStream()))
        response = ""
        line = input_stream.readLine()
        while line is not None:
            response += line
            line = input_stream.readLine()
        input_stream.close()

        result = json.loads(response)
        return result.get("response", "")
    except Exception as e:
        print("Error communicating with Ollama: ", str(e))
        return None

def extract_json(text):
    try:
        start = text.index('{')
        end = text.rindex('}') + 1
        json_str = text[start:end]
        return json.loads(json_str)
    except ValueError:
        print("No JSON found in response.")
        return None

def rename_function_with_ollama(currentProgram, func):
    decomp = DecompInterface()
    decomp.openProgram(currentProgram)
    monitor = ConsoleTaskMonitor()
    decompiled = decomp.decompileFunction(func, 30, monitor)

    if not decompiled or not decompiled.getDecompiledFunction():
        print("Failed to decompile function: ", func.getName())
        return

    code = decompiled.getDecompiledFunction().getC()

    prompt = (
        "Вы специалист по обратному проектированию. Ниже приведен код функции на языке Си. "
        "Возвращайте ТОЛЬКО JSON-файл с новым именем функции на латинеце, которое является описательным и значимым "
        "Example: {\"function_name\": \"ValidateUserInput\"}\n\n"
        "Code:\n"
        + code
    )

    new_code = send_to_ollama(prompt)
    if new_code:
        print("Suggested data for " + func.getName() + ":\n", new_code)
        parse_and_rename(currentProgram, func, new_code)
    else:
        print("Failed to get response from Ollama for " + func.getName())

def parse_and_rename(currentProgram, func, response):
    data = extract_json(response)
    if data:
        if 'function_name' in data:
            new_name = data['function_name']
            if new_name != func.getName():
                func.setName(new_name, SourceType.USER_DEFINED)
                print("Function renamed: " + func.getName() + " -> " + new_name)
            else:
                print("Function name unchanged: " + func.getName())
    else:
        print("Failed to extract JSON for " + func.getName())

def main():
    fm = currentProgram.getFunctionManager()
    functions = fm.getFunctions(True)  # True = forward order

    for func in functions:
        # Пропускаем библиотечные функции
        if func.isExternal() or func.getSymbol().getSource() != SourceType.DEFAULT:
            continue
        print("Processing function: " + func.getName())
        rename_function_with_ollama(currentProgram, func)

main()
