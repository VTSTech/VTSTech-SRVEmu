# -*- coding: utf-8 -*-
# @category VTSTech_PS2
# @author VTSTech

import json
from ghidra.program.model.mem import MemoryAccessException

def get_string_at_addr(addr):
    """
    Reads bytes until null terminator and decodes safely.
    """
    program = getCurrentProgram()
    memory = program.getMemory()
    
    try:
        string_bytes = []
        offset = 0
        while offset < 512: # Increased limit for longer strings
            b = memory.getByte(addr.add(offset))
            if b == 0:
                break
            # Convert signed byte to unsigned (0-255)
            string_bytes.append(b & 0xFF)
            offset += 1
        
        # Convert byte list to a byte string
        byte_str = "".join(chr(b) for b in string_bytes)
        
        # Safety: Decode as Latin-1 to avoid UTF-8 crashes (Latin-1 maps 1:1 to bytes 0-255)
        # Then encode/decode to clean up non-printable characters if needed
        return byte_str.decode('latin-1').encode('utf-8', 'replace').decode('utf-8')

    except MemoryAccessException:
        return "Error: Memory Access"
    except Exception as e:
        return "Error: " + str(e)

def run():
    program = getCurrentProgram()
    symbol_table = program.getSymbolTable()
    
    results = {
        "metadata": {
            "program_name": program.getName(),
            "base_address": program.getImageBase().toString(),
        },
        "strings": []
    }

    # Iterate through all symbols
    for symbol in symbol_table.getAllSymbols(True):
        name = symbol.getName()
        
        if name.startswith("STR_") or name.startswith("s_"):
            addr = symbol.getAddress()
            
            # Use our safe string extractor
            string_val = get_string_at_addr(addr)
            
            entry = {
                "address": "0x" + addr.toString(),
                "name": name,
                "value": string_val,
                "offset": addr.getOffset()
            }
            results["strings"].append(entry)

    # Output selection
    try:
        output_file = askFile("Select output JSON file", "Save")
        if output_file:
            # Open with explicit encoding for Jython
            import codecs
            with codecs.open(output_file.getAbsolutePath(), 'w', encoding='utf-8') as f:
                json_str = json.dumps(results, indent=4, ensure_ascii=False)
                f.write(json_str)
            print("Successfully exported {} strings.".format(len(results["strings"])))
    except Exception as e:
        print("Final Export Error: {}".format(e))

if __name__ == "__main__":
    run()
