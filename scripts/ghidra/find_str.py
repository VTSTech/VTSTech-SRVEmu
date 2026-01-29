# -*- coding: utf-8 -*-
#@category PS2_NASCAR
#@author Gemini
# Scans for DAT_ entries that are strings and renames them to STR_<Content>

from ghidra.program.model.symbol import SourceType
from ghidra.program.model.data import StringDataType
import re

# Maximum length for the name to avoid overly long symbols
MAX_LABEL_LENGTH = 30

def sanitize_name(original):
    # Remove non-alphanumeric characters for a clean label
    clean = re.sub(r'[^a-zA-Z0-9]', '_', original)
    # Remove multiple underscores
    clean = re.sub(r'_+', '_', clean)
    return clean.strip('_')

def main():
    symbol_table = getCurrentProgram().getSymbolTable()
    listing = getCurrentProgram().getListing()
    
    renamed_count = 0
    
    # Iterate through all symbols in the program
    for symbol in symbol_table.getAllSymbols(True):
        name = symbol.getName()
        address = symbol.getAddress()
        
        # Only target default DAT_ labels
        if name.startswith("DAT_"):
            # Check if there is defined data at this address
            data = listing.getDataAt(address)
            
            # If not defined, try to see if Ghidra can see a string here
            # (Ghidra often identifies strings even if they aren't 'defined' yet)
            string_val = None
            
            if data and data.hasStringValue():
                string_val = data.getValue()
            else:
                # If it's undefined, let's try to "peek" at the bytes to see if it's a string
                try:
                    # We check the first few bytes for printable characters
                    bytes_to_check = getBytes(address, 16)
                    chars = []
                    for b in bytes_to_check:
                        # PS2/ASCII printable range
                        if 32 <= (b & 0xFF) <= 126:
                            chars.append(chr(b & 0xFF))
                        elif b == 0:
                            break
                        else:
                            break
                    
                    if len(chars) > 0: # Only bother if it's at least 0 chars
                        string_val = "".join(chars)
                except:
                    pass

            if string_val:
                clean_str = sanitize_name(string_val)
                if clean_str:
                    # Truncate if too long
                    if len(clean_str) > MAX_LABEL_LENGTH:
                        clean_str = clean_str[:MAX_LABEL_LENGTH]
                    
                    new_name = "STR_" + clean_str
                    
                    # Check for collisions (if two addresses contain the same string)
                    existing_symbols = symbol_table.getSymbols(new_name)
                    if existing_symbols:
                        new_name = new_name + "_" + address.toString()

                    print("Renaming " + name + " (" + address.toString() + ") -> " + new_name)
                    symbol.setName(new_name, SourceType.USER_DEFINED)
                    renamed_count += 1

    print("-" * 60)
    print("STRING RENAMING SUMMARY")
    print("Successfully renamed: " + str(renamed_count))
    print("-" * 60)

if __name__ == "__main__":
    main()