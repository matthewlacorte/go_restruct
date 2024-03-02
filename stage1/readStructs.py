#Find all calls to runtime.newobject()
#@author Matthew LaCorte
#@category Capstone
#@keybinding 
#@menupath 
#@toolbar 

import json
import time

from ghidra.app.plugin.core.colorizer import ColorizingService
from ghidra.app.script import GhidraScript

from ghidra.program.model.listing import Data

from ghidra.program.model.address.Address import *
from ghidra.program.model.listing.CodeUnit import *
from ghidra.program.model.listing.Listing import *

from ghidra.program.model.util import *

TEST_STRUCT = '1098da0'


# Error out with message
def err(msg):
    printerr(msg)
    exit(0)


def readFile(file):

    # Read file
    lines = ''
    with open(file, 'r') as f:
        lines = f.readline()

    # Split read line by curly bracket
    tmp = lines.split('},')
    newlines = []

    # Fix formatting and add to list of objects
    for t in tmp:
        if t.startswith('['):
            newlines.append(t[1:]+'}')
        elif t.endswith(']'):
            newlines.append(t[:-1])
        elif t.endswith('"'):
            newlines.append(t+'}')

    # Read objects into list of JSON objects
    dicts = []
    for l in newlines:
        dicts.append(json.loads(l))
    
    
    # Return list of dict objects
    return dicts



# Trim struct output file to only struct addresses
def trimStructs(structs):

    addr_strs = []
    addrs = []

    # For all structs, append new address strings to list
    for s in structs:
        addr = str(s['struct'])
        # print(addr)
        if addr not in addr_strs:
            # if TEST_STRUCT in addr: # TODO : remove
                # print('yeup')
            addr_strs.append(addr)
    
    # For all address strings, convert to Address objects
    for addr in addr_strs:
        addr = currentProgram.getAddressFactory().getAddress(addr)
        addrs.append(addr)
    
    # Return list of Addresses
    return addrs



# Find all pointers in structs
def readData(structs):

    # TODO : Need to convert non-pointers to pointers
        # Always at base+56?

    listed = {}

    # For all struct addresses...
    for struct in structs:
        
        # Find class name of struct
        class_name = 'unknown'
        try:
            # TODO : What to do if no class name present?
            class_name = getClassName(struct)
        except:
            pass

        # Find pointers within them
        field_pointers = findPointer(struct)

        # Append pointers to dict list of struct address
        listed[struct] = {}
        listed[struct]['fields'] = field_pointers
        listed[struct]['class'] = class_name

    
    # Return dict of struct: [address, ]
    return listed


# Evaluate if value is a valid pointer
def validPointer(addr):

    valid = False

    # Clear 8 bytes
    # TODO This should be 4 bytes for 32-bit?
    start_addr = addr
    end_addr = addr.add(8)
    currentProgram.getListing().clearCodeUnits(addr, end_addr, False)

    # Try and make pointer
    try:
        currentProgram.getListing().createData(start_addr, ghidra.program.model.data.PointerDataType(), 8)
    except:
        valid = False
        return valid

    # Print data
    data = currentProgram.getListing().getDataAt(start_addr).getValue()

    # Test if valid
    valid = currentProgram.getAddressFactory().isValidAddress(data)

    # Other test for valid address
    val = int(str(data), 16)

    # TODO : How should this change?
    if (val > 0x01000000) and (val < 0x02000000):
        valid = True
    else:
        valid = False

    # If not valid, clear data type
    if not valid:
        currentProgram.getListing().clearCodeUnits(addr, end_addr, False)


    return valid


# Find all pointers in data structure and save to list of [address, data]
# Field names will always be two pointers back to back (0x00, 0x08)
# followed by an offset value
#   0x00 - field name string
#   0x08 - some data
#   0x10 - offset value
# If 0x18 does hold another pointer, keep going
# If 0x18 does not hold another pointer, stop looking
def findPointer(struct_addr):

    # Get pointer to struct definition
    # TODO : will it always be +0x38 ??? - I THINK SO


    # Set start and end address of pointer to field name section
    start_addr = struct_addr.add(0x38)
    end_addr = struct_addr.add(0x38+0x8) # TODO : 4/8 for 32/64? 

    # Clear any existing data structure there. Add new pointer
    currentProgram.getListing().clearCodeUnits(start_addr, end_addr, True)
    currentProgram.getListing().createData(start_addr, ghidra.program.model.data.PointerDataType(), 4) # TODO : SHould this be 4/8 depending on 32/64 bit?

    # Get value of pointer to field name section
    struct_def = currentProgram.getListing().getDataAt(struct_addr.add(56)).getValue()

    # Holds pointers
    pnts = []

    # Setting variables...
    addr = struct_def
    is_pointer = True
    
    # While previous was pointer...
    while (is_pointer):
        # Check if this is pointer
        is_pointer = validPointer(addr)
        
        # If it is a pointer...
        if is_pointer:
            # Create pointers for next 8 as well
            currentProgram.getListing().createData(addr.add(0x8), ghidra.program.model.data.PointerDataType(), 0x8) # TODO : 4/8 for 32/64?
            pnts.append(addr)

        # Next field would be defined 0x18 ahead
        addr = addr.add(0x18)
    

    # TODO : library of struct (string) is at +48
        # Calculated the same way as field names

    return pnts


# Get string for class name of struct
# Done same as finding field strings, but starts 48 after struct definition
def getClassName(struct_addr):

    start_addr = struct_addr.add(0x30)
    end_addr = struct_addr.add(0x30+0x8) # 4/8 for 32/64?

    # Clear any existing data structure there. Add new pointer
    currentProgram.getListing().clearCodeUnits(start_addr, end_addr, False)
    currentProgram.getListing().createData(start_addr, ghidra.program.model.data.PointerDataType(), 8) # TODO : SHould this be 4/8 depending on 32/64 bit?


    # Get address pointed to
    addr = currentProgram.getListing().getDataAt(start_addr).getValue()


    # Clear code units of first two bytes (for getting string len)
    currentProgram.getListing().clearCodeUnits(addr, addr.add(1), False)
    

    # Get string length
    len = data2int(addr.add(1))
    # print('len is ' + str(len))

    # Set start and end of string addresses (based on len found)
    start = addr.add(2)
    end = addr.add(2+len-1)

    # Clear code units from start to end of string locations
    currentProgram.getListing().clearCodeUnits(start, end, False)

    # Create data from start, of type string, with found length
    currentProgram.getListing().createData(start, ghidra.program.model.data.StringDataType(), len) # testing this
    
    # Save found string
    name = currentProgram.getListing().getDataAt(addr.add(2)).getValue()

    # Create label at field name address
    createLabel(addr, 'class_'+name, True)

    return name





# Takes in data address. returns char value of data
# TODO : Do this
def data2char(addr):
    print('Converting type to string...')

    # Get data
    data = currentProgram.getListing().getDataAt(addr)

    # Get type of data
    typeof = str(data.getDataType())
    ret = ''

    print(typeof)

    # Get correct part and transform, based on data type
    if typeof == 'byte':
        ret = chr(int(data.getValue()), 16)
    elif typeof == 'int':
        ret = chr(data.getValue())
    elif typeof == 'string':
        ret = data.getValue()[0]
    
    print(ret)

    return ret


# Takes in data address. returns char value of data
def data2int(addr):
    ret = ''

    # Get data
    data = currentProgram.getListing().getDataAt(addr)

    # Get type of data and value
    typeof = str(data.getDataType())
    val = data.getValue()

    # Get correct part and transform, based on data type
    if typeof == 'byte':
        # ret = int(data.getValue())
        ret = int(str(val), 16)
    elif typeof == 'int':
        # ret = data.getValue()
        ret = int(val, 16)
    elif typeof == 'string':
        # ret = ord(data.getValue()[0])
        ret = ord(val[0])
    elif typeof == 'undefined':
        ret = int(str(val), 16)

    # Return integer value
    return ret


# Associate field names from dict of structs
def associateFieldNames(structs):

    # For all structs...
    for struct in structs:

        # if TEST_STRUCT in str(struct):
        #     print('HERE HERE HERE HERE HERE HERE HERE HERE HERE HERE HERE HERE HERE')
        
        # If there are pointers found in it...
        if len(structs[struct]['fields']) > 0:

            # Try to get field names
            try:
                field_names = readFieldNames(structs[struct]['fields'])
                
                # Set names in dict
                structs[struct]['field_names'] = field_names
            except:
                print('\n\nFailed for ' + str(struct) + ' ###########################################################################\n\n')

    # Return dict of structs
    return structs





# Read names of fields
def readFieldNames(pointers):

    field_names = []

    # For all pointers in list...
    for p in pointers:

        # Find referenced location
        point = currentProgram.getListing().getDataAt(p).getValue()

        # Clear code units of first two bytes (for getting string len)
        currentProgram.getListing().clearCodeUnits(point, point.add(1), True)

        # Calculate length of string (held at base+1 address)
        len = data2int(point.add(1))
        # print('len is : ' , len)

        # Set start and end of string addresses (based on len found)
        start = point.add(2)
        end = point.add(2+len)

        # Clear code units from start to end of string locations
        currentProgram.getListing().clearCodeUnits(start, end, True)

        # Create data from start, of type string, with found length
        currentProgram.getListing().createData(start, ghidra.program.model.data.StringDataType(), len) # testing this
        
        # Save found string
        field_name = currentProgram.getListing().getDataAt(point.add(2)).getValue()
        field_names.append([point, field_name])

        # Create label at field name address
        createLabel(point, 'field_'+field_name, True)
    
    
    return field_names

# Associate calling instructions with structs
def associateCalling(structs_raw, structs):

    # For all struct newobject calls...
    for s in structs_raw:
        # Get address of struct and instruction it was created
        addr = currentProgram.getAddressFactory().getAddress(str(s['struct']))
        instr = currentProgram.getAddressFactory().getAddress(str(s['instruction']))

        # Append instruction to dict of structs. Create new list if not existing
        if 'instructions' in structs[addr].keys():
            structs[addr]['instructions'].append(instr)
        else:
            structs[addr]['instructions'] = [instr]

    # Return duct of structs
    return structs


# Write info to file
def writeToFile2(structs):

    data = {}

    # Convert dict to strings
    for struct in structs:
        data[str(struct)] = {}

        for key in structs[struct]:
            data[str(struct)][str(key)] = str(structs[struct][key])

    # Write
    file = '/Users/mlc/ghidra_scripts/capstone/outputs/readStructs.txt'
    with open(file, 'w+') as f:
        f.write(json.dumps(data))

# main func for testing
def main():

    # Hello info
    print('Finding all field names of structs')

    # Run previous script to get all struct locations
    print('Running \'findAllNewObject.py\'')
    runScript('findAllNewObject.py')
    print('Finished running \'findAllNewObject.py\'')

    # Variables to use...
    structs_raw = []        # Holds list of structs/instructions from previous script
    addresses = []          # Holds list of struct definition addresses
    struct_pointers = []    # Holds list of pointers at each struct definition
    structs = []            # Holds list of struct dicts, with addresses of fields and names associated

    # Read previously saved data
    file = '/Users/mlc/ghidra_scripts/capstone/outputs/findAllNewObject.txt'
    structs_raw = readFile(file)

    print(structs_raw)

    exit(0)

    # Convert data to list of addresses of structs
    addresses = trimStructs(structs_raw)

    # Get list of pointers at addresses
    struct_pointers = readData(addresses)

    # Get strings of field names for each struct
    structs = associateFieldNames(struct_pointers)
    
    # Associate addresses where structs are created with struct definitions
    structs = associateCalling(structs_raw, structs)

    # Write info to file
    writeToFile2(structs)


    return

# init
if __name__ == '__main__':
    start_time = time.time()
    main()
    print("--- %s seconds ---" % (time.time() - start_time))
