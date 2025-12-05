# -*- coding: utf-8 -*-
#@category VTSTech_PS2
#!/usr/bin/env python
# Match functions between NASCAR Thunder 2004 and NBA Street Vol. 3

from ghidra.app.script import GhidraScript
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.data import StringDataType
import json
import os
import re
import time

def analyze_network_functions():
    """Complete analysis of network functions"""
    
    println("=" * 70)
    println("NETWORK PROTOCOL ANALYSIS - NBA STREET VOL. 3")
    println("=" * 70)
    
    program = currentProgram
    func_manager = program.getFunctionManager()
    
    # Key network functions we've identified
    key_network_functions = {
        '0x4d53a8': 'ProtoAriesSecure',
        '0x4d4f28': 'ProtoAriesSend', 
        '0x4d5258': 'ProtoAriesRecv',
        '0x4d7d90': 'LobbyApiUpdate',
        '0x4d2ec0': 'RpcCall',
        '0x4d2ef0': 'RpcBind',
        '0x4d3040': 'RpcElapsed',
        '0x4d49e8': 'ProtoAriesCreate',
        '0x4d4ba8': 'ProtoAriesConnect',
        '0x4d4cf0': 'ProtoAriesUnconnect',
        '0x4d4d90': 'ProtoAriesStatus',
        '0x4d4f20': 'ProtoAriesUpdate',
        '0x4d5070': 'ProtoAriesRecvCB',
        '0x4d5090': 'ProtoAriesPeek',
        '0x4d54b8': 'ProtoAriesTick'
    }
    
    println("\nANALYZING KEY NETWORK FUNCTIONS:")
    println("-" * 70)
    
    function_analysis = {}
    
    for hex_addr, func_name in key_network_functions.items():
        try:
            addr = toAddr(int(hex_addr, 16))
            func = func_manager.getFunctionAt(addr)
            
            if func:
                # Get function details
                func_data = {
                    'name': func.getName(),
                    'address': hex_addr,
                    'size': func.getBody().getNumAddresses(),
                    'calls': [],
                    'called_by': []
                }
                
                # Get functions this calls
                called_funcs = func.getCalledFunctions(monitor)
                for called in called_funcs:
                    func_data['calls'].append({
                        'name': called.getName(),
                        'address': hex(called.getEntryPoint().getOffset())
                    })
                
                # Get functions that call this one
                refs = program.getReferenceManager().getReferencesTo(addr)
                caller_set = set()
                for ref in refs:
                    if ref.getReferenceType().isCall():
                        caller_func = func_manager.getFunctionContaining(ref.getFromAddress())
                        if caller_func:
                            caller_set.add(caller_func.getName())
                
                func_data['called_by'] = list(caller_set)[:10]  # First 10 callers
                
                function_analysis[func_name] = func_data
                
                println(func_name.ljust(25) + " @ " + hex_addr)
                println("  Size: " + str(func_data['size']) + " bytes")
                println("  Calls: " + str(len(func_data['calls'])) + " functions")
                println("  Called by: " + str(len(func_data['called_by'])) + " functions")
                
        except Exception as e:
            println("[ERROR] " + func_name + " @ " + hex_addr + ": " + str(e))
    
    # Analyze specific functions for encryption/decryption
    println("\nENCRYPTION/DECRYPTION ANALYSIS:")
    println("-" * 70)
    
    encryption_funcs = ['ProtoAriesSend', 'ProtoAriesRecv', 'ProtoAriesSecure']
    
    for func_name in encryption_funcs:
        if func_name in function_analysis:
            func_data = function_analysis[func_name]
            println("\n" + func_name + " Analysis:")
            println("  Calls these key functions:")
            
            # Look for encryption-related calls
            crypto_keywords = ['Rpc', 'Secure', 'Crypt', 'Hash', 'MD5', 'RC4']
            crypto_calls = []
            
            for call in func_data['calls']:
                call_name = call['name']
                for keyword in crypto_keywords:
                    if keyword in call_name:
                        crypto_calls.append(call_name)
                        break
            
            if crypto_calls:
                for call_name in crypto_calls[:5]:  # Show first 5
                    println("    - " + call_name)
            else:
                println("    No obvious crypto function calls found")
    
    # Find string references for protocol commands
    println("\nPROTOCOL COMMAND STRING ANALYSIS:")
    println("-" * 70)
    
    protocol_strings = [
        'RC4+MD5-V2',
        '@tic', '@dir', '@key', '@addr',
        'VERS=', 'SKU=', 'SLUS=', 'LANG=', 'MID=', 'FROM=',
        'ADDR=', 'PORT=', 'DATA_PORT=', 'SESS=', 'MASK=', 'STATUS='
    ]
    
    # Search memory for these strings
    memory = program.getMemory()
    string_findings = {}
    
    for block in memory.getBlocks():
        if block.isInitialized():
            try:
                addr = block.getStart()
                end = block.getEnd()
                
                # Simple string search (basic approach)
                current_string = ""
                current_addr = addr
                
                while current_addr < end:
                    byte_val = getByte(current_addr)
                    
                    if 32 <= byte_val < 127:  # Printable ASCII
                        current_string += chr(byte_val)
                    else:
                        if len(current_string) >= 4:
                            # Check if this string contains any protocol patterns
                            for search_str in protocol_strings:
                                if search_str in current_string:
                                    if search_str not in string_findings:
                                        string_findings[search_str] = []
                                    
                                    # Get function that references this string
                                    ref_addr = current_addr.subtract(len(current_string))
                                    refs = program.getReferenceManager().getReferencesTo(ref_addr)
                                    for ref in refs:
                                        func = func_manager.getFunctionContaining(ref.getFromAddress())
                                        if func:
                                            func_name = func.getName()
                                            func_addr = hex(func.getEntryPoint().getOffset())
                                            string_findings[search_str].append({
                                                'function': func_name,
                                                'address': func_addr,
                                                'string_addr': hex(ref_addr.getOffset()),
                                                'string': current_string[:50]  # First 50 chars
                                            })
                                        break
                                    break
                        
                        current_string = ""
                    
                    current_addr = current_addr.add(1)
                    
            except:
                pass
    
    # Display string findings
    for search_str, findings in string_findings.items():
        if findings:
            println("\n'" + search_str + "' found in:")
            for finding in findings[:3]:  # Show first 3
                println("  " + finding['function'] + " @ " + finding['address'])
                println("    String: " + finding['string'])
    
    # Save comprehensive report
    output_dir = os.path.expanduser("~/Desktop")
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    report_file = os.path.join(output_dir, "nba_street_network_analysis_" + timestamp + ".json")
    
    full_report = {
        'key_functions': function_analysis,
        'string_findings': string_findings,
        'analysis_timestamp': timestamp
    }
    
    with open(report_file, 'w') as f:
        json.dump(full_report, f, indent=2)
    
    # Create summary for patching
    println("\n" + "=" * 70)
    println("PATCHING RECOMMENDATIONS:")
    println("=" * 70)
    
    println("\nBased on analysis, here are the key functions to patch:")
    println("-" * 70)
    
    patch_recommendations = [
        ("ProtoAriesSecure (0x4d53a8)", "Patch to return immediately or NOP RpcBind/RpcCall calls"),
        ("LobbyApiUpdate (0x4d7d90)", "Patch encryption decision logic at 0x004D7DF4 and 0x004D7E08"),
        ("ProtoAriesSend (0x4d4f28)", "May need patching if data is still encrypted"),
        ("ProtoAriesRecv (0x4d5258)", "May need patching if expecting encrypted data")
    ]
    
    for func_desc, recommendation in patch_recommendations:
        println(func_desc)
        println("  " + recommendation)
        println()
    
    println("Current patches we've tried:")
    println("1. Patch at 0x004D7DF4: beq s0,zero -> beq zero,zero (force no encryption branch)")
    println("2. Patch at 0x004D7E08: beql v0,zero -> nop (skip encryption check)")
    println("3. Patch ProtoAriesSecure at 0x004D53A8: return immediately")
    println("4. Patch @tic send at 0x004D8134: nop")
    
    println("\n" + "=" * 70)
    println("ANALYSIS COMPLETE!")
    println("Full report saved to: " + report_file)
    println("=" * 70)

# Run the script
if __name__ == "__main__" or __name__ == "__builtin__":
    analyze_network_functions()