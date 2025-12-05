# -*- coding: utf-8 -*-
#@category VTSTech_PS2
#@keybinding 
#@menupath 
#@toolbar 
# Ghidra Jython script to list all renamed functions
# Output format similar to functions.txt

from ghidra.app.script import GhidraScript
from ghidra.program.model.symbol import SymbolType

def main():
    program = getCurrentProgram()
    listing = program.getListing()
    symbolTable = program.getSymbolTable()
    
    print("================================================================================")
    print("RENAMED FUNCTIONS LIST")
    print("================================================================================\n")
    
    # Get all functions
    functionManager = program.getFunctionManager()
    functions = functionManager.getFunctions(True)  # True = forward iteration
    
    renamed_count = 0
    total_count = 0
    
    for function in functions:
        total_count += 1
        func_name = function.getName()
        func_addr = function.getEntryPoint()
        
        # Skip functions with default names
        if (func_name.startswith("FUN_") or 
            func_name.startswith("LAB_") or 
            func_name.startswith("undefined") or
            func_name.startswith("thunk_") or
            func_name == ""):
            continue
        
        # Format: FunctionName -> 0xAddress
        print(func_name + " -> " + "0x" + format(func_addr.getOffset(), '08x'))
        renamed_count += 1
    
    print("\n" + "=" * 80)
    print("SUMMARY:")
    print("Total functions: " + str(total_count))
    print("Renamed functions: " + str(renamed_count))
    print("Unnamed functions: " + str(total_count - renamed_count))
    print("=" * 80)

if __name__ == "__main__":
    main()
