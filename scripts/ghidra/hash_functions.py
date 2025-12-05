# -*- coding: utf-8 -*-
#@category VTSTech_PS2
#!/usr/bin/env python
# Export function signatures from NASCAR Thunder 2004
# Save to: nascar_functions.json

from ghidra.app.script import GhidraScript
import hashlib
import json
import re
import os
import time
from collections import OrderedDict

def get_simple_function_signature(func):
    """Create a simple signature for a function"""
    program = currentProgram
    listing = program.getListing()
    
    signature = {
        'name': func.getName(),
        'address': hex(func.getEntryPoint().getOffset()),
        'size': func.getBody().getNumAddresses()
    }
    
    # Get first 20 instructions (simplified)
    instr_pattern = []
    addr = func.getEntryPoint()
    end = func.getBody().getMaxAddress()
    
    count = 0
    while addr < end and count < 20:
        instr = listing.getInstructionAt(addr)
        if not instr:
            break
        
        # Skip nops
        if instr.getMnemonicString() != 'nop':
            instr_str = instr.toString()
            # Simplify by removing specific addresses
            if '0x' in instr_str:
                # Replace hex addresses with placeholder
                import re
                instr_str = re.sub(r'0x[0-9a-f]+', 'ADDR', instr_str)
            instr_pattern.append(instr_str)
            count += 1
        
        addr = addr.add(instr.getLength())
    
    signature['instructions'] = instr_pattern
    
    # Get called functions
    called_funcs = []
    refs = func.getCalledFunctions(monitor)
    for called in refs:
        called_funcs.append(called.getName())
    
    signature['calls'] = called_funcs[:10]  # First 10
    
    # Create hash
    hash_input = '|'.join(instr_pattern) + '|' + '|'.join(called_funcs[:10])
    signature['hash'] = hashlib.md5(hash_input.encode()).hexdigest()
    
    return signature

# Main execution
def main():
    println("=" * 60)
    println("NASCAR Thunder 2004 Function Exporter")
    println("=" * 60)
    
    # Try multiple locations to save files
    possible_dirs = [
        os.path.expanduser("~/Desktop"),  # Desktop
        os.path.dirname(os.path.abspath(__file__)),  # Script directory
        os.getcwd(),  # Current working directory
        "C:/Users/VTSTech/Desktop"  # Explicit desktop path
    ]
    
    output_dir = None
    for test_dir in possible_dirs:
        if os.path.exists(test_dir):
            output_dir = test_dir
            println("Found writable directory: " + test_dir)
            break
    
    if not output_dir:
        println("ERROR: No writable directory found!")
        return
    
    println("Output directory: " + output_dir)
    
    # Get all functions
    program = currentProgram
    func_manager = program.getFunctionManager()
    funcs = list(func_manager.getFunctions(True))
    
    println("Total functions: " + str(len(funcs)))
    
    # Export named functions
    function_data = {}
    named_count = 0
    
    for func in funcs:
        name = func.getName()
        
        # Only export named functions (skip auto-generated names)
        if not name.startswith('FUN_') and not name.startswith('LAB_') and not name.startswith('DAT_'):
            if func.getBody().getNumAddresses() > 10:
                signature = get_simple_function_signature(func)
                function_data[name] = signature
                named_count += 1
                
                if named_count % 25 == 0:
                    println("Processed " + str(named_count) + " named functions...")
    
    println("\nNamed functions found: " + str(named_count))
    
    # Save to file
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    filename = "nascar_functions_" + timestamp + ".json"
    filepath = os.path.join(output_dir, filename)
    
    try:
        with open(filepath, 'w') as f:
            json.dump(function_data, f, indent=2)
        
        println("\nSUCCESS: File created!")
        println("Location: " + filepath)
        
        # Verify file was created
        if os.path.exists(filepath):
            file_size = os.path.getsize(filepath)
            println("File size: " + str(file_size) + " bytes")
        else:
            println("WARNING: File may not have been created!")
        
        # Also create a smaller index file
        index_data = {}
        for name, sig in function_data.items():
            index_data[name] = {
                'hash': sig['hash'][:12],  # First 12 chars of hash
                'addr': sig['address'],
                'size': sig['size']
            }
        
        index_file = "nascar_index_" + timestamp + ".json"
        index_path = os.path.join(output_dir, index_file)
        
        with open(index_path, 'w') as f:
            json.dump(index_data, f, indent=2)
        
        println("Index file: " + index_path)
        
    except Exception as e:
        println("ERROR saving file: " + str(e))
    
    # Show what was exported
    println("\n" + "=" * 60)
    println("SAMPLE OF EXPORTED FUNCTIONS:")
    println("-" * 60)
    
    count = 0
    for name, sig in function_data.items():
        if count < 10:  # Show first 10
            println(name + " @ " + sig['address'])
            println("  Hash: " + sig['hash'][:16] + "...")
            println("  Calls: " + str(len(sig['calls'])) + " functions")
            if sig['instructions']:
                println("  First instruction: " + sig['instructions'][0])
            println()
            count += 1
    
    println("=" * 60)
    println("Check your Desktop for the JSON files!")
    println("Files should be named: nascar_functions_*.json")
    println("and nascar_index_*.json")

# Run the script
if __name__ == "__main__" or __name__ == "__builtin__":
    main()