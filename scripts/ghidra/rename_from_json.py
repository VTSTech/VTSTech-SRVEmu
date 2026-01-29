# -*- coding: utf-8 -*-
# @category PS2_NASCAR
# @author Gemini
# @keybinding 
# @menupath 
# @toolbar 

from ghidra.app.script import GhidraScript
from ghidra.program.model.symbol import SourceType
import json
import os

def main():
    # The script expects functions.json to be in the same directory as the script
    script_dir = os.path.dirname(getSourceFile().getAbsolutePath())
    json_path = os.path.join(script_dir, "functions.json")
    
    print("Expected JSON path: {}".format(json_path))
    
    if not os.path.exists(json_path):
        print("ERROR: functions.json not found at the expected path.")
        return

    # Load the JSON data
    try:
        with open(json_path, 'r') as f:
            data = json.load(f)
    except Exception as e:
        print("ERROR: Failed to parse JSON: {}".format(str(e)))
        return

    functions = data.get("functions", [])
    program = getCurrentProgram()
    
    renamed_count = 0
    failed_count = 0
    skipped_count = 0

    print("EA Sports NASCAR Thunder 2004 - JSON Function Renamer")
    print("=" * 60)
    print("Processing {} functions from JSON...".format(len(functions)))

    for entry in functions:
        addr_str = entry.get("address")
        name = entry.get("name")
        
        if not addr_str or not name:
            continue
            
        # Convert hex string to Ghidra Address
        addr = toAddr(addr_str)
        
        if addr is None:
            print("ERROR: Invalid address {}".format(addr_str))
            failed_count += 1
            continue

        func = getFunctionAt(addr)
        
        if func is not None:
            old_name = func.getName()
            
            # Skip if already has a specific name
            if not old_name.startswith("FUN_") and not old_name.startswith("LAB_") and not old_name.startswith("undefined"):
                print("SKIP: {} already named '{}'".format(addr_str, old_name))
                skipped_count += 1
                continue
                
            try:
                func.setName(name, SourceType.USER_DEFINED)
                print("OK:   {} '{}' -> '{}'".format(addr_str, old_name, name))
                renamed_count += 1
            except Exception as e:
                print("ERROR: {} Failed to rename: {}".format(addr_str, str(e)))
                failed_count += 1
        else:
            # Try to create function if it doesn't exist
            try:
                createFunction(addr, name)
                print("CREATE: {} Created '{}'".format(addr_str, name))
                renamed_count += 1
            except Exception as e:
                print("ERROR: {} Failed to create: {}".format(addr_str, str(e)))
                failed_count += 1

    print("\n" + "=" * 60)
    print("RENAMING SUMMARY")
    print("Successfully renamed/created: {}".format(renamed_count))
    print("Skipped:                      {}".format(skipped_count))
    print("Failed:                       {}".format(failed_count))

if __name__ == "__main__":
    main()