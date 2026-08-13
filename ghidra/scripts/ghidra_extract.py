# ghidra_extract.py
# @category Analysis

import sys
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

def run():
    program = getCurrentProgram()
    decomp = DecompInterface()
    decomp.openProgram(program)
    
    args = getScriptArgs()
    output_path = args[0] if len(args) > 0 else "raw_decompiled.c"
    
    fm = program.getFunctionManager()
    functions = fm.getFunctions(True)
    
    with open(output_path, "w") as f:
        for func in functions:
            if func.isExternal() or func.isThunk():
                continue
                
            results = decomp.decompileFunction(func, 60, ConsoleTaskMonitor())
            if results.decompiledFunction:
                f.write("// FUNCTION_START: %s\n" % func.getName())
                f.write(results.decompiledFunction.getC())
                f.write("\n// FUNCTION_END\n\n")

run()