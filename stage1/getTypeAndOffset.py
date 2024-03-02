#Find all calls to runtime.newobject()
#@author Matthew LaCorte
#@category Capstone
#@keybinding 
#@menupath 
#@toolbar 

import json
import time
import sys

from ghidra.app.plugin.core.colorizer import ColorizingService
from ghidra.app.script import GhidraScript

from ghidra.program.model.listing import Data

from ghidra.program.model.address.Address import *
from ghidra.program.model.listing.CodeUnit import *
from ghidra.program.model.listing.Listing import *

from ghidra.program.model.util import *

TEST_STRUCT = '1098da0'

''' CLASSES '''

# Class of StructField
#    Name   Name
#    Typ    *Type
#    Offset uintptr
class field:
    def __init__(self):
        self.name = 'n/a'
        self.name_address = 0x0
        self.type = 0
        self.type_address = 0x0
        self.offset = 0
        self.offset_address = 0x0
    
    def __str__(self):
        return 'Name:{0} Type:{1} Offset:{2}'.format(self.name, self.type, self.offset)
    
    name = 'n/a'
    name_address = 0x0
    type = 0
    type_address = 0x0
    offset = 0
    offset_address = 0x0

# Class of Struct
#   Type
#	PkgPath Name
#	Fields  []StructField
class struct:
    def __init__(self):
        self.base_address = 0x0
        self.name = 'n/a'
        self.package = 'n/a'
        self.fields = []
    
    base_address = 0x0
    name = 'Not yet'
    package = 'n/a'
    fields = []

    def __str__(self):
        return 'Name:{0} Package:{1} Fields:{2}'.format(self.name, self.package, str(self.fields))






''' Definition of commonly used calls '''

# Get address object from address string
def getAddress(addr):
    return currentProgram.getAddressFactory().getAddress(addr)


# Clear data between addresses
def clearCodeUnits(start_addr, end_addr, clear_refs):
    currentProgram.getListing().clearCodeUnits(start_addr, end_addr, clear_refs)


# Define data starting at start_addr, of type data_type, for length of len
def createData(start_addr, data_type, len):
    currentProgram.getListing().createData(start_addr, data_type, len)


# Get data at defined address
def getDataAt(addr):
    return currentProgram.getListing().getDataAt(addr)


# Check if defined address if valid
def isValidAddress(addr):
    return currentProgram.getAddressFactory().isValidAddress(addr)


''' End definition of commonly used calls '''





# Error out with message
def err(msg):
    printerr(msg)
    exit(0)



''' COOL STUFF '''


# Go through all functions and make list of names + entry points
def getAllFuncs():

    # Hold all functions & entry point addresses
    functions = {}

    # Holds entry point address of runtime.newobject()
    func_runtime_newobject = ''

    # Iterate all functions
    func = getFirstFunction()

    while func is not None:
        # print(func.getName(), func.getEntryPoint())
        functions[str(func.getName())] = func.getEntryPoint()

        # Get next function
        func = getFunctionAfter(func)

    # If runtime.newobject() is functions dict
    if 'runtime.newobject' in functions.keys():
        # Save address of runtime.newobject() as string with 0x in front
        func_runtime_newobject = '0x' + str(functions['runtime.newobject'])
    else:
        # No runtime.newobject() function. Error out
        err('Could not find runtime.newobject() function. Exiting...')

    # Return runtime.newobject address and all functions
    return func_runtime_newobject, functions

        
# Get all instructions
def getAllInstructions(func_runtime_newobject):

    # Variables to use
    instructions = []   # Holds all instruction addresses
    call_newobj = {}    # Holds all call instructions 
    structs = []        # Holds all struct addresses

    # Iterate through all instructions
    instr = getFirstInstruction()
    while instr is not None:
        # print(instr.getMinAddress(), instr.getMnemonicString())
        instructions.append(instr)

        # If instruction is CALL 0x...
        if instr.getMnemonicString() == u'CALL':
            # If call is to runtime.newobject()...
            if str(instr.getDefaultOperandRepresentation(0)) == func_runtime_newobject:

                # Look back through previous instructions to find where EAX/RAX was assigned
                for i in range(len(instructions) + 1):
                    tmpi = instructions[-1 * i]
                    if tmpi.getMnemonicString() == 'LEA':
                        # print(tmpi)
                        if tmpi.getDefaultOperandRepresentation(0) == 'RAX':
                            # Add struct address to list
                            structs.append(tmpi.getDefaultOperandRepresentation(1))

                            # Add instruction + struct to dict
                            call_newobj[instr.getMinAddress()] = {
                                'instruction': instr,
                                'struct': str(tmpi.getDefaultOperandRepresentation(1)[1:-1])
                            }

                            # found it!
                            break
                        elif tmpi.getDefaultOperandRepresentation(0) == 'EAX':
                            # Add struct address to list
                            structs.append(tmpi.getDefaultOperandRepresentation(1))
                            
                            # Add instruction + struct to dict
                            call_newobj[instr.getMinAddress()] = {
                                'instruction': instr,
                                'struct': str(tmpi.getDefaultOperandRepresentation(1)[1:-1])
                            }

                            # found it!
                            break
        
        # Get next instruction
        instr = instr.getNext()
    
    
    return instructions, call_newobj, structs


# Trim struct output file to only struct addresses
def trimStructs(structs):

    # Variables to use...
    addr_strs = []      # List of strings of struct definition addresses
    addrs = []          # List of addresses of struct definition addresses

    # For all struct newobject calls...
    for key in structs:

        # Address of struct
        addr = str(structs[key]['struct'])

        # If address not saved, save it
        if addr not in addr_strs:
            addr_strs.append(addr)
        
    # For all address strings, convert to Address objects
    for addr in addr_strs:
        addr = getAddress(addr)

        # If Struct type identified...
        if verifyStruct(addr):
            # Append to list of structs
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
    clearCodeUnits(addr, end_addr, False)

    # Try and make pointer
    try:
        createData(start_addr, ghidra.program.model.data.PointerDataType(), 8)
    except:
        valid = False
        return valid

    # Print data
    data = getDataAt(start_addr).getValue()

    # Test if valid
    valid = isValidAddress(data)

    # Other test for valid address
    val = int(str(data), 16)

    # TODO : How should this change?
    if (val > 0x010000) and (val < 0x02000000):
        valid = True
    else:
        valid = False

    # If not valid, clear data type
    if not valid:
        clearCodeUnits(addr, end_addr, False)


    return valid

# TODO : Clean me
# Look for magic 0x19 @ base+0x17. Magic number signifies it is a Struct type
def verifyStruct(address):

    # Try in case it fails...
    try:
        # Get data at type number address
        magic = getDataAt(address.add(0x17)).getValue().getValue()

        # 0x19 is Golang number for struct type
        if magic == 0x19:
            # Return is struct
            return True
        else:
            # Return is not struct
            return False
    # Whoopsie case
    except:
        return False





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
    clearCodeUnits(start_addr, end_addr, True)
    createData(start_addr, ghidra.program.model.data.PointerDataType(), 4) # TODO : SHould this be 4/8 depending on 32/64 bit?

    # Get value of pointer to field name section
    struct_def = getDataAt(struct_addr.add(56)).getValue()

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
            createData(addr.add(0x8), ghidra.program.model.data.PointerDataType(), 0x8) # TODO : 4/8 for 32/64?
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
    clearCodeUnits(start_addr, end_addr, False)
    createData(start_addr, ghidra.program.model.data.PointerDataType(), 8) # TODO : SHould this be 4/8 depending on 32/64 bit?


    # Get address pointed to
    addr = getDataAt(start_addr).getValue()


    # Clear code units of first two bytes (for getting string len)
    clearCodeUnits(addr, addr.add(1), False)
    

    # Get string length
    len = data2int(addr.add(1))
    # print('len is ' + str(len))

    # Set start and end of string addresses (based on len found)
    start = addr.add(2)
    end = addr.add(2+len-1)

    # Clear code units from start to end of string locations
    clearCodeUnits(start, end, False)

    # Create data from start, of type string, with found length
    createData(start, ghidra.program.model.data.StringDataType(), len) # testing this
    
    # Save found string
    name = getDataAt(addr.add(2)).getValue()

    # Create label at field name address
    createLabel(addr, 'class_'+name, True)

    return name





# Takes in data address. returns char value of data
# TODO : Do this
def data2char(addr):
    print('Converting type to string...')

    # Get data
    data = getDataAt(addr)

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
    data = getDataAt(addr)

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
        point = getDataAt(p).getValue()

        # Clear code units of first two bytes (for getting string len)
        clearCodeUnits(point, point.add(1), True)

        # Calculate length of string (held at base+1 address)
        len = data2int(point.add(1))
        # print('len is : ' , len)

        # Set start and end of string addresses (based on len found)
        start = point.add(2)
        end = point.add(2+len)

        # Clear code units from start to end of string locations
        clearCodeUnits(start, end, True)

        # Create data from start, of type string, with found length
        createData(start, ghidra.program.model.data.StringDataType(), len) # testing this
        
        # Save found string
        field_name = getDataAt(point.add(2)).getValue()
        field_names.append([point, field_name])

        # Create label at field name address
        createLabel(point, 'field_'+field_name, True)
    
    
    return field_names

# Associate calling instructions with structs
def associateCalling(structs_raw, structs):

    # For all struct newobject calls...
    for struct in structs_raw:
        # Get address of struct and instruction it was created
        addr = getAddress(struct['struct'])
        instr = getAddress(struct['instruction'])

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
    file = '/Users/mlc/ghidra_scripts/capstone/outputs/getSizeAndOffset.txt'
    with open(file, 'w+') as f:
        f.write(json.dumps(data))

    return


# All steps of original findAllNewObject.py script in one function
def findAllNewObject():
    
    # Hello info
    print
    print('[+] Finding all calls to runtime.newobject() and locations of structs used')


    # Variables to use...
    functions = {}
    instructions = []
    call_newobj = {}
    structs = []
    func_runtime_newobject = ''


    # Get newobject address and all functions
    func_runtime_newobject, functions = getAllFuncs()

    # Get all instructions, calls to newobject(), and struct addresses
    instructions, call_newobj, structs = getAllInstructions(func_runtime_newobject)

    print('\t[-] ' + str(len(call_newobj.keys())) + ' calls found...')

    # call_newobj is what I want
    return call_newobj




# All steps of original readStructs.py script in one function
def getFields(call_newobj):

    # Hello info
    print
    print('[+] Finding all field names of structs')

    # Variables to use...
    structs_raw = []        # Holds list of structs/instructions from previous script
    addresses = []          # Holds list of struct definition addresses
    struct_pointers = []    # Holds list of pointers at each struct definition
    structs = []            # Holds list of struct dicts, with addresses of fields and names associated


    # Convert data to list of addresses of structs
    addresses = trimStructs(call_newobj)

    # Get list of pointers at addresses
    struct_pointers = readData(addresses)

    # Get strings of field names for each struct
    structs = associateFieldNames(struct_pointers)
    
    # Associate addresses where structs are created with struct definitions
    structs = associateCalling(structs_raw, structs)

    print('\t[-] ' + str(len(structs.keys())) + ' structs identified...')

    print('\n\nTesting size getting...')
    # structs = findSizes(structs)

    # Write info to file
    writeToFile2(structs)


    return structs



# Find all sizes and offsets of types
def findSizes(structs):

    # For all structs...
    for struct in structs:

        # If list of field names is present...
        if 'field_names' in structs[struct].keys():
        
            # Set some vars
            fields = structs[struct]['fields']      # Previous list of all field locations
            names = structs[struct]['field_names']  # Previous list of all field names & name addresses
            true_fields = []                        # New list of all fields (field objects)

            i = 0   # name counter

            # For all fields...
            for f in fields:
                # TODO : 4/8 for 32/64?
                # Clear data where size and offset are saved
                clearCodeUnits(f.add(8), f.add(16), False)
                # clearCodeUnits(f.add(16), f.add(24), False)

                # TODO : 4/8 for 32/64?
                # Create data types where size and offset are saved
                createData(f.add(8), ghidra.program.model.data.PointerDataType(), 4)
                createData(f.add(16), ghidra.program.model.data.IntegerDataType(), 4)

                # Create field object
                tmpfield = field()

                # Get field name & name address from previous list
                tmpfield.name = str(names[i][1])
                tmpfield.name_address = names[i][0]

                # TODO : 4/8 for 32/64?
                # Get value at pointer to data size
                tmpfield.size = getDataAt(getDataAt(f.add(8)).getValue()).getValue()
                tmpfield.size_address = f.add(8)

                # TODO : 4/8 for 32/64?
                # Get value of offset
                tmpfield.offset = getDataAt(f.add(16)).getValue()
                tmpfield.offset_address = f.add(16)

                # Append field object to list of them
                true_fields.append(tmpfield)

                i += 1 # Iterate name counter
            
            # Add list of fields to structs
            structs[struct]['real_fields'] = true_fields
   

    # Return modified dict
    return structs




''' NEW STUFF '''
# Get the kind of each field in the struct
def getKind(base_address, s):

    # Only run on test case now...
    if str(base_address) == '00492880':
        print(base_address)
        print(s)
        print
        
        # Get all StructFields
        field_addresses = s['fields']

        # For all fields...
        for f in field_addresses:
            # Get pointer to Type*
            type_at = getDataAt(f.add(8)).getValue()
            print(type_at)
            # Get magic number of type
            type = getDataAt(type_at.add(0x17)).getValue().getValue()
            print(types[type])

            # Type is index from global Type list
            type_str = types[type]
            print


# For all structs...
def getKinds(structs):

    # Get the kind of each element in the struct
    for struct in structs:
        getKind(struct, structs[struct])






''' END NEW STUFF '''







# main func for testing
def main():

    # Variables to use...
    call_newobj = {}    # Dict of all calls to runtime.newobject(), holds struct definition address and address of call
    structs = []        # List of all struct definitions

    # Get addresses of all newobject() calls and structs associated
    call_newobj = findAllNewObject()

    # Parse all found structs for field names
    structs = getFields(call_newobj)


    getKinds(structs)
    


    return



# Define some global variables
def init():
    global types
    types = [
        'Invalid',
        'Bool',
        'Int',
        'Int8',
        'Int16',
        'Int32',
        'Int64',
        'Uint',
        'Uint8',
        'Uint16',
        'Uint32',
        'Uint64',
        'Uintptr',
        'Float32',
        'Float64',
        'Complex64',
        'Complex128',
        'Array',
        'Chan',
        'Func',
        'Interface',
        'Map',
        'Pointer',
        'Slice',
        'String',
        'Struct',
        'UnsafePointer',
    ]

    global pointer_size
    pointer_size = currentProgram.getDefaultPointerSize()

    return




# init
if __name__ == '__main__':

    init()

    # Save start time
    start_time = time.time()
    
    # Do the thing
    main()

    # Calculate running time
    print
    print("--- %s seconds ---" % (time.time() - start_time))
