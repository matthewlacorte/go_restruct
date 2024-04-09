#Test ability to track read/write ops of structs
#@author Matthew LaCorte
#@category Capstone
#@keybinding 
#@menupath 
#@toolbar 

import json
import time
import sys
import os


from ghidra.app.plugin.core.colorizer import ColorizingService
from ghidra.app.script import GhidraScript

from ghidra.program.model.listing import Data

from ghidra.program.model.address.Address import *
from ghidra.program.model.listing.CodeUnit import *
from ghidra.program.model.listing.Listing import *

from ghidra.program.model.util import *

from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.data import DataTypeConflictHandler


POINTER_SIZE_BYTES = currentProgram.getDefaultPointerSize()
POINTER_SIZE_BITS = 8*POINTER_SIZE_BYTES
# Set for 32-bit
REG_AX = 'EAX'
# Alter if 64-bit
if POINTER_SIZE_BYTES == 8:
    REG_AX = 'RAX'

# TODO : Anywhere that passes by value, stop it
#   Python is pass by reference natively, so no need for tmp edits


''' CLASSES '''

# Class of StructField
#    Name   Name
#    Typ    *Type
#    Offset uintptr
class field_class:
    def __init__(self):
        self.base_address = 0x0
        self.name = 'n/a'
        self.name_address = 0x0
        self.type = 0
        self.type_address = 0x0
        self.offset = 0
        self.offset_address = 0x0
    
    def __str__(self):
        return 'Name:{0} Type:{1} Offset:{2}'.format(self.name, types[self.type], hex(self.offset).strip('L'))
    
    base_address = 0x0
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
class struct_class:
    def __init__(self):
        self.base_address = 0x0
        self.name = 'n/a'
        self.name_offset = 0x0
        self.package = 'n/a'
        self.fields = []
        self.temp_fields = []
        self.data_structure = ''
        self.data_structure_name = 'n/a'
    
    # TODO : Add size value and retrieve
        
    base_address = 0x0
    name = 'Not yet'
    name_offset = 0x0
    package = 'n/a'
    fields = []
    tmp_fields = []

    data_structure = ''
    data_structure_name = 'n/a'

    def __str__(self):
        return 'Name:{0} Fields:{1} tmpFields:{2}'.format(self.package, str(self.fields), str(self.tmp_fields))
    
    # Pretty print the struct w/ fields
    def printme(self):
        try:
            print(self.name + ' : ' + str(self.base_address))
            for f in self.fields:
                if len(f.name) <= 10:
                    # hex(f.offset)[:-1] to turn int to hex, cutting of 'L' at the end of the hex
                    print('\t' + str(hex(f.offset)[:-1]) + '\t' + f.name + '\t\t' + types[f.type])
                else:
                    # hex(f.offset)[:-1] to turn int to hex, cutting of 'L' at the end of the hex
                    print('\t' + str(hex(f.offset)[:-1]) + '\t' + f.name + '\t' + types[f.type])
        except:
            print('nah for ' + str(self.base_address))
            for f in self.fields:
                print('\t' + str(f))

''' END CLASSES '''


# Output all structs to a .txt file
def saveStructs(structs):
    print('Printing all structs...')

    # Prompt user to save structs to a file
    save = askYesNo('Save structs?', 'Save structs to an output .txt file?')
    if not save:
        return

    # Write all structs & fields to lines
    lines = []
    for struct in structs:
        lines.append(struct.name + ' @ ' + str(struct.base_address) + '\n')
        for field in struct.fields:
            lines.append('\t' + field.name + ' ' + hex(field.offset).strip('L') + ' ' + types[field.type] + '\n')
        lines.append('\n')

    # Prompt user for file to output structs to
    grsfile = askFile("Go ReStruct output file", "Choose Go ReStruct output file")
    with open(grsfile.getAbsolutePath(), "w+") as fp:
        fp.writelines(lines)



''' Definition of commonly used calls '''

# Get address object from address string
def getAddress(addr):
    return currentProgram.getAddressFactory().getAddress(addr)


# Clear data between addresses
def clearCodeUnits(start_addr, end_addr, clear_refs):
    listing.clearCodeUnits(start_addr, end_addr, clear_refs)


# Define data starting at start_addr, of type data_type, for length of len
def createData(start_addr, data_type, len):
    listing.createData(start_addr, data_type, len)


# Get data at defined address
def getDataAt(addr):
    return listing.getDataAt(addr)


# Check if defined address if valid
def isValidAddress(addr):
    return currentProgram.getAddressFactory().isValidAddress(addr)


# Error out with message
def err(msg):
    printerr(msg)
    exit(0)



''' End definition of commonly used calls '''



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
                        if tmpi.getDefaultOperandRepresentation(0) == REG_AX:
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

    tmp_structs = []    # List of structs

    # For all struct addresses...
    for struct in structs:
        # Create new struct object
        tmp_struct = struct_class()

        # Assign base address from input
        tmp_struct.base_address = struct

        # Find package name of struct and assign
        package_name = 'n/a'
        try:
            package_name = getPackageName(struct)
            tmp_struct.package = package_name
        except:
            pass
        
        # Find pointers within struct. Assign to tmp field
        tmp_struct.tmp_fields = findPointer(struct)

        # Append struct to list of structs
        tmp_structs.append(tmp_struct)
    
        
    # Return list of structs
    return tmp_structs



# Evaluate if value is a valid pointer
def validPointer(addr):

    valid = False

    # Clear 8 bytes
    start_addr = addr
    end_addr = addr.add(POINTER_SIZE_BYTES)
    clearCodeUnits(addr, end_addr, False)

    # Try and make pointer
    try:
        createData(start_addr, ghidra.program.model.data.PointerDataType(), POINTER_SIZE_BYTES)
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
    if (val > 0x01000) and (val < 0x02000000):
        valid = True
    else:
        valid = False

    # If not valid, clear data type
    if not valid:
        clearCodeUnits(addr, end_addr, False)


    return valid


# Look for magic 0x19 @ base+0x17. Magic number signifies it is a Struct type
def verifyStruct(address):
    
    # Try in case it fails...
    try:
        # Get data at type number address
        magic = getDataAt(address.add(0x17)).getValue().getValue()
        magic = (0x1f & magic)

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
    # Set start and end address of pointer to field name section
    start_addr = struct_addr.add(0x38)
    end_addr = struct_addr.add(0x38+POINTER_SIZE_BYTES)

    # Clear any existing data structure there. Add new pointer
    clearCodeUnits(start_addr, end_addr, True)
    createData(start_addr, ghidra.program.model.data.PointerDataType(), POINTER_SIZE_BYTES)

    # Get value of pointer to field name section
    struct_def = getDataAt(struct_addr.add(56)).getValue() # TODO : Does 56 include pointer lengths?

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
            createData(addr.add(POINTER_SIZE_BYTES), ghidra.program.model.data.PointerDataType(), POINTER_SIZE_BYTES)
            pnts.append(addr)

        # Next field would be defined 0x18 ahead
        addr = addr.add(0x18)

    return pnts


# Get string for class name of struct
# Done same as finding field strings, but starts 48 after struct definition
def getPackageName(struct_addr):

    start_addr = struct_addr.add(0x30)
    end_addr = struct_addr.add(0x30+0x8) # 4/8 for 32/64?

    # Clear any existing data structure there. Add new pointer
    clearCodeUnits(start_addr, end_addr, False)
    createData(start_addr, ghidra.program.model.data.PointerDataType(), POINTER_SIZE_BYTES)


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

        # TODO : Better way for this?
        # If there are pointers found in it...
        if len(struct.tmp_fields) > 0:

            # Try to get field names
            try:
                fields = readFieldNames(struct.tmp_fields)
                
                # Set names in struct object
                struct.fields = fields

            except:
                pass
            
    # Return list of all structs
    return structs




# Read names of fields
def readFieldNames(pointers):

    fields = []

    for p in pointers:
        tmp_field = field_class()
        tmp_field.base_address = p

        # Find referenced location and save to field object
        point = getDataAt(p).getValue()
        tmp_field.name_address = point

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
        
        # Save found string to field object
        field_name = getDataAt(point.add(2)).getValue()
        tmp_field.name = field_name
        tmp_field.name_address = point

        # Create label at field name address
        createLabel(point, 'field_'+field_name, True)

        # Append field to list of fields
        fields.append(tmp_field)


    return fields




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




# All steps of original findAllNewObject.py script in one function
def findAllNewObject():
    
    # Hello info
    print
    print('[+] Finding all calls to runtime.newobject()...')


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

    print('\t[-] ' + str(len(call_newobj.keys())) + ' calls found')

    # call_newobj is what I want
    return call_newobj



def getStructs(call_newobj):
    # Hello info
    print
    print('[+] Finding all structs...')

    # Variables to use...
    structs_raw = []        # Holds list of structs/instructions from previous script
    addresses = []          # Holds list of struct definition addresses
    struct_pointers = []    # Holds list of pointers at each struct definition
    structs = []            # Holds list of struct dicts, with addresses of fields and names associated

    # Convert data to list of addresses of structs
    addresses = trimStructs(call_newobj)

    # print(len(addresses))

    # Get list of pointers at addresses
    structs = readData(addresses)

    # Print some info 
    print('\t[-] ' + str(len(structs)) + ' structs identified')

    return structs



# Get the magic number (kind) of each field and save it to the field object
def getFieldKind(field):
    # Type pointer is at base_address+0x8
    field.type_address = getDataAt(field.base_address.add(POINTER_SIZE_BYTES)).getValue()

    # Type magic number is at type_address+0x17
    type_of = getDataAt(field.type_address.add(0x17)).getValue().getValue() # double get value because first is ghidra.scalar, second is value

    # Set type value
    #   AND w/ 0x1a because the type values get too big sometimes
    #   0x1a is the biggest the struct type can be
    field.type = (0x1f & type_of)

    # Return field object
    return field



# Get the kind associated with each field
def getFieldKinds(structs):

    # For every struct...
    for struct in structs:
        # Set tmp list of fields
        # tmp_fields = []

        # For every field...
        for field in struct.fields:

            # Get the kind of the field
            getFieldKind(field)

            # Save new field object to tmp list
            # tmp_fields.append(tmp_field)
        
        # Set fields to tmp list of fields
        # struct.fields = tmp_fields

    # Return list of structs
    # return structs


# Ge the field offset
def getFieldOffset(field):

    # Offset is held at base_address+0x16
    field.offset_address = field.base_address.add(0x10)
    
    # Clear and set data at offset address as an integer (32/64 based)
    if REG_AX == 'EAX':
        clearCodeUnits(field.offset_address, field.offset_address.add(0x3), False) # TODO : Long only if 64-bit
        createData(field.offset_address, ghidra.program.model.data.IntegerDataType(), 4) # TODO : Long only if 64-bit
    else:
        clearCodeUnits(field.offset_address, field.offset_address.add(0x7), False) # TODO : Long only if 64-bit
        createData(field.offset_address, ghidra.program.model.data.LongDataType(), 8) # TODO : Long only if 64-bit

    # Read data (integer) at offset address
    field.offset = getDataAt(field.offset_address).getValue().getValue()

# Get the offset for each field
def getFieldOffsets(structs):

    # For every struct...
    for struct in structs:
        # For every field in the struct...
        for field in struct.fields:
            # Get the field offset
            getFieldOffset(field)


# All steps of original readStructs.py script in one function
def getFields(orig_structs):

    # Hello info
    print
    print('[+] Finding all field of structs...')

    # Variables to use...
    structs_raw = []        # Holds list of structs/instructions from previous script
    addresses = []          # Holds list of struct definition addresses
    struct_pointers = []    # Holds list of pointers at each struct definition
    structs = []            # Holds list of struct dicts, with addresses of fields and names associated

    # Get strings of field names for each struct
    structs = associateFieldNames(orig_structs)

    getFieldKinds(structs)

    getFieldOffsets(structs)

    print('\t[-] All fields found')
    return structs






# Create dict of base address (key) of struct with struct object
def createStructAddressDict(structs):
    
    struct_addresses = {}   # Empty dict for structs queried by base address

    # For all structs...
    for struct in structs:
        # Save to dict (base_address -> struct_object)
        struct_addresses[struct.base_address] = struct

    # Return dict of all structs
    return struct_addresses



# Link all calls to runtime.newobject() with the struct used in them
def associate(call_newobj, struct_addresses):

    print
    print('[+] Associating calls with structs...')
    
    struct_calls = {}   # Empty dict to place associations in

    # For all calls to runtime.newobject()...
    for c in call_newobj:
        # Create address object
        # TODO : can this be an address from the start?
        addr = getAddress(call_newobj[c]['struct'])
        
        # If address found is a struct that is saved...
        if addr in struct_addresses.keys():
            # Associate calling address with definition
            struct_calls[c] = struct_addresses[addr]
    
    print('\t[-] ' + str(len(struct_calls)) + ' calls asssociated')

    # Return dict of calls to runtime.newobject with struct definition addresses
    return struct_calls




# Read the offset value for the name field, then read the string from rodata+offset
def getName(rodata_addr, struct):
    
    # NameOff field (name offset from rodata) is an integer starting at base_address+0x2b
    # Clear data their then create integer data type at it
    clearCodeUnits(struct.base_address.add(0x28), struct.base_address.add(0x2b), False)
    createData(struct.base_address.add(0x28), ghidra.program.model.data.IntegerDataType(), 4)

    # Read offset value
    offset = getDataAt(struct.base_address.add(0x28)).getValue().getValue()

    # Save offset value
    struct.name_offset = offset

    # Calculate address of name string from rodata + offset
    name_address = rodata_addr.add(offset)

     # Get string length
    len = data2int(name_address.add(1))

    # Set start and end of string addresses (based on len found)
    start = name_address.add(2)
    end = name_address.add(2+len-1)

    # Clear code units from start to end of string locations
    clearCodeUnits(start, end, False)

    # Create data from start, of type string, with found length
    createData(start, ghidra.program.model.data.StringDataType(), len) # testing this
    
    # Get name string
    name = getDataAt(name_address.add(2)).getValue()

    # Remove astrisk if at the front
    if name[0] == '*':
        name = name[1:]
    
    # Save name
    struct.name = name

    return


# Go through all structs and get their names
def getNames(structs):

    # Get .rodata memory block
    rodata_addr = None
    for block in getMemoryBlocks():
        if 'rodata' in block.getName():
            rodata_addr = block.getStart()
    
    # If rodata can be found...
    if rodata_addr is not None:
        # For all structs...
        for struct in structs:
            # Get their name from the NameOff value
            getName(rodata_addr, struct)
    

''' End detect functions '''

''' Start markup functions'''

# Function to set EOL comment at address
def setCommentEOL(addr, comment):
    codeUnit = listing.getCodeUnitAt(addr)
    codeUnit.setComment(CodeUnit.EOL_COMMENT, comment)


# Function to set PRE comment at address
def setCommentPRE(addr, comment):
    codeUnit = listing.getCodeUnitAt(addr)
    codeUnit.setComment(CodeUnit.PRE_COMMENT, comment)
    



# Set comments with struct name at all locations where runtime.newobject() is called (for structs)
def markupNewObjCalls(structs, struct_calls):
    # print('Marking up newObj calls...')
    print
    print('[+] Commenting all runtime.newobject() initializations for structs...')

    cnt = 0
    
    # For all calls to runtime.newobject()...
    for addr in struct_calls:
        cnt += 1

        # Set the comment as 'runtime.newobject(struct_name) - struct_base_address
        comment = 'runtime.newobject(' + struct_calls[addr].name + ') - ' + str(struct_calls[addr].base_address)
        setCommentPRE(addr, comment)

    print('\t[-] ' + str(cnt) + ' runtime.newobject() calls commented')
    
    return


# Clear all comments in the binary
def clearAllComments():

    print
    print('[+] Clearing all comments... (testing)')

    # Get min and max address of program
    min = currentProgram.getMinAddress()
    max = currentProgram.getMaxAddress()

    # Get start and end of .text section to clear instead
    blocks = getMemoryBlocks()
    for b in blocks:
        if '.text' in b.getName():
            min = b.getStart()
            max = b.getEnd()

    # Clear all comments
    try:
        listing.clearComments(min, max)
        print('\t[-] All comments removed')
    except:
        print('\t\t[x] Error removing previous comments')


    return


''' End markup functions (for now) '''






''' Start read/write detection '''

# Find location that struct gets saved too after runtime.newobject()
def findWhereSaved(struct_calls):
    print
    print('[+] Finding all struct field read and write locations...')

    reads = []
    writes = []

    # One to test with is 01088c80 in struct_calls.keys()

    # For all calls to runtime.newobject()...
    for c in struct_calls:
        
        # Get containing function info
        func = listing.getFunctionContaining(c)

        # Get first instruction
        instr = listing.getInstructionAt(c).getNext()

        # Set initial info
        current_holds = [REG_AX]

        # For all instructions in function...
        # TODO : How to account for differing paths (if/else, JMPs, etc)
        while (listing.getFunctionContaining(instr.getAddress()) == func):
            
            if 'CALL' in instr.getMnemonicString():
                if REG_AX in current_holds:
                    current_holds.remove(REG_AX)
            
            # If it is a MOV type instruction///
            if 'MOV' in instr.getMnemonicString():

                # Get to/fro elems in MOV op
                to = str(instr.getDefaultOperandRepresentation(0))
                fro = str(instr.getDefaultOperandRepresentation(1))

                # Format to/fro if pointers (decided by presence of '[]')
                to_ptr = False
                fro_ptr = False

                if '[' in to:
                    to = to[to.index('[') : to.index(']')+1]
                    to_ptr = True
                if '[' in fro:
                    fro = fro[fro.index('[') : fro.index(']')+1]
                    fro_ptr = True
                
                # If first MOV elem is being overwritten, remove from tracked list
                if (to in current_holds) and (not to_ptr):
                    current_holds.remove(to)

                # If second MOV elem is in tracked list, add first elem to tracked list
                if (fro in current_holds) and (not fro_ptr):
                    if to not in current_holds:
                        current_holds.append(to)

                # If to elem is a pointer...
                if to_ptr:
                    # For all locations that hold the struct...
                    for hold in current_holds:
                        # If hold location is in pointer, but not full pointer...
                        if (hold in to) and (hold != to):

                            off = 0
                            name = ''

                            # If offset present, calculate it
                            if '+' in to:
                                off = int(str(to[1:-1].split('+')[-1].strip(' ')), 16)
                            
                            # From offset value, find the field
                            for field in struct_calls[c].fields:
                                if field.offset == off:
                                    name = field.name
                            
                            # Set comment. "(W) structName.fieldName"
                            setCommentEOL(instr.getAddress(), '(W) ' + struct_calls[c].name.split('.')[-1] + '.' + name)
                            
                            # Add to list of writes
                            writes.append([instr.getAddress(), 'W', struct_calls[c], field])
                        
                        # TODO : Find where base pointer is written to. Ex - "MOV qword ptr [RSP + local_100], RAX"

                            
                # If fro elem is a pointer...
                if fro_ptr:
                    # For all locations that hold the struct...
                    for hold in current_holds:
                        # If hold location is in pointer, but not full pointer...
                        if (hold in fro) and (hold != fro):

                            off = 0
                            name = ''

                            # If offset present, calculate it
                            if '+' in fro:
                                off = int(str(fro[1:-1].split('+')[-1].strip(' ')), 16)
                            
                            # From offset value, find the field
                            for field in struct_calls[c].fields:
                                if field.offset == off:
                                    name = field.name
                                    print('\toff - ' + str(off) + ' ' + field.name)
                            
                            # Set comment. "(R) structName.fieldName"
                            setCommentEOL(instr.getAddress(), '(R) ' + struct_calls[c].name.split('.')[-1] + '.' + name)
                            
                            # Add to list of reads
                            reads.append([instr.getAddress(), 'R', struct_calls[c], field])

            instr = instr.getNext()
    
    print('\t[-] ' + str(len(reads)) + ' read locations identified')
    print('\t[-] ' + str(len(writes)) + ' write locations identified')
    
    return reads, writes

''' End read/write detection '''




''' Start Data Structure section '''

# Create data structure in Ghidra based off of found Go Struct
# Returns 1 on successful creation, 0 if not
def createDataStructure(struct, dataTypeManager, category_path):

    # TODO : MORE DATA TYPES
    dtm = dataTypeManager

    # Data type setting
    un1 = dtm.getDataType('/undefined1')
    un2 = dtm.getDataType('/undefined2')
    un4 = dtm.getDataType('/undefined4')
    un8 = dtm.getDataType('/undefined8')

    int8 = dtm.getDataType('/types.h/int8_t')
    int16 = dtm.getDataType('/short')
    int32 = dtm.getDataType('/types.h/int32_t')
    int64 = dtm.getDataType('/types.h/int64_t')

    uint8 = dtm.getDataType('/stdint.h/uint8_t')
    uint16 = dtm.getDataType('/stdint.h/uint16_t')
    uint32 = dtm.getDataType('/stdint.h/uint32_t')
    uint64 = dtm.getDataType('/stdint.h/uint64_t')
    
    float32 = dtm.getDataType('/float')
    float64 = dtm.getDataType('/float8')

    bool = dtm.getDataType('/bool')

    string = dtm.getDataType('/char *')

    pointer = dtm.getDataType('/pointer')
    uint_ptr = dtm.getDataType('/stdint.h/uintptr_t')

    # If data types not available -> set as undefined X length
    if int8 == None: int8 = dtm.getDataType('/undefined1')
    if int16 == None: int16 = dtm.getDataType('/undefined2')
    if int32 == None: int32 = dtm.getDataType('/undefined4')
    if int64 == None: int64 = dtm.getDataType('/undefined8')

    if uint8 == None: uint8 = dtm.getDataType('/undefined1')
    if uint16 == None: uint16 = dtm.getDataType('/undefined2')
    if uint32 == None: uint32 = dtm.getDataType('/undefined4')
    if uint64 == None: uint64 = dtm.getDataType('/undefined8')

    if float32 == None: float32 = dtm.getDataType('/undefined4')
    if float64 == None: float64 = dtm.getDataType('/undefined8')

    if bool == None: bool = dtm.getDataType('/undefined1')

    if string == None: string = dtm.getDataType('/undefined8')

    if pointer == None:
        if REG_AX == 'EAX':
            pointer = dtm.getDataType('/undefined4')
        else:
            pointer = dtm.getDataType('/undefined8')

    if uint_ptr == None:
        if REG_AX == 'EAX':
            uint_ptr = dtm.getDataType('/undefined4')
        else:
            uint_ptr = dtm.getDataType('/undefined8')


    # Set the data types
    try:

        # Counter stuff
        max_offset = 0
        last_len = 0

        # For all fields...
        # TODO : Does not work for extended length items such as arrays
        for field in struct.fields:
            # Get field length + offset
            len_to_use = type_lens[types[field.type]]
            max_offset = field.offset
            last_len = type_lens[types[field.type]]
        
        # Calculate total length of struct
        total_len = max_offset + last_len


        # Create Ghidra data structure
        # TODO : Why does the base address really matter?
        # test_struct = ghidra.program.model.data.StructureFactory.createStructureDataType(currentProgram, struct.base_address, total_len, struct.name, True)
        test_struct = ghidra.program.model.data.StructureFactory.createStructureDataType(currentProgram, currentProgram.getMinAddress(), total_len, struct.name, True)


        # Delete all bytes
        for i in range(test_struct.getLength()):
            test_struct.deleteAtOffset(i)
        
        # For every field in the struct...
        for field in struct.fields:
            
            # Increase Struct size if not aligned with offset
            if field.offset > test_struct.getLength():
                test_struct.growStructure(field.offset-test_struct.getLength())

            # For all different types, add the correct Ghidra DataType into the offset position of the data structure
            if field.type == 0:
                print('error')
            elif field.type == 0x01: # bool
                test_struct.add(bool, 1, field.name, field.name)
            
            # # # Integers # # #
            elif field.type == 0x02: # int
                if REG_AX == 'EAX':
                    test_struct.add(int32, 4, field.name, field.name)
                else:
                    test_struct.add(int64, 8, field.name, field.name)
            elif field.type == 0x03: # int8
                test_struct.add(int8, 1, field.name, field.name)
            elif field.type == 0x04: # int16
                test_struct.add(int16, 2, field.name, field.name)
            elif field.type == 0x05: # int32
                test_struct.add(int32, 4, field.name, field.name)
            elif field.type == 0x06: # int64
                test_struct.add(int64, 8, field.name, field.name)

            # # # Unsigned Integers # # #
            elif field.type == 0x07: # uint
                if REG_AX == 'EAX':
                    test_struct.add(uint32, 4, field.name, field.name)
                else:
                    test_struct.add(uint64, 8, field.name, field.name)
            elif field.type == 0x08: # uint8
                test_struct.add(uint8, 1, field.name, field.name)
            elif field.type == 0x09: # uint16
                test_struct.add(uint16, 2, field.name, field.name)
            elif field.type == 0x0a: # uint32
                test_struct.add(uint32, 4, field.name, field.name)
            elif field.type == 0x0b: # uint64
                test_struct.add(uint64, 8, field.name, field.name)
            elif field.type == 0x0c: # uintptr
                test_struct.add(uint_ptr, 8, field.name, field.name)

            # # # Float & Complex # # #
            elif field.type == 0x0d: # float32
                test_struct.add(float32, 4, field.name, field.name)
            elif field.type == 0x0e: # float64
                test_struct.add(float64, 8, field.name, field.name)
            
            elif field.type == 0x0f: # complex64
                test_struct.add(un4, 4, field.name+'_real', field.name + '_real')
                test_struct.add(un4, 4, field.name+'_imag', field.name + '_imag') # 2-piece
            elif field.type == 0x10: # complex128
                test_struct.add(un8, 8, field.name+'_real', field.name + '_real')
                test_struct.add(un8, 8, field.name+'_imag', field.name + '_imag') # 2-piece

            # # # Go Specific # # #
            # TODO : Do all the below
            elif field.type == 0x11: # array
                test_struct.add(un1, 1, field.name, field.name)
            elif field.type == 0x12: # chan
                test_struct.add(un1, 1, field.name, field.name)
            elif field.type == 0x13: # func
                test_struct.add(pointer, POINTER_SIZE_BYTES, field.name, field.name)
            elif field.type == 0x14: # interface
                test_struct.add(un1, 1, field.name, field.name)
            elif field.type == 0x15: # map
                test_struct.add(un1, 1, field.name, field.name)
            elif field.type == 0x16: # pointer
                test_struct.add(pointer, POINTER_SIZE_BYTES, field.name, field.name)
            elif field.type == 0x17: # slice
                test_struct.add(un1, 1, field.name, field.name)

            elif field.type == 0x18: # string
                if REG_AX == 'EAX':
                    test_struct.add(string, POINTER_SIZE_BYTES, field.name+'_ptr', field.name + '_ptr')
                    test_struct.add(int32, 4, field.name+'_len', field.name + '_len') # 2-piece
                else:
                    test_struct.add(string, POINTER_SIZE_BYTES, field.name+'_ptr', field.name + '_ptr')
                    test_struct.add(int64, 8, field.name+'_len', field.name + '_len') # 2-piece

            elif field.type == 0x19: # struct
                test_struct.add(un8, POINTER_SIZE_BYTES, field.name, field.name)

            elif field.type == 0x20: # unsafePointer
                test_struct.add(pointer, POINTER_SIZE_BYTES, field.name, field.name)
        
        # Add the data structure to the DataTypeManager
        test_struct.setCategoryPath(category_path)
        data_type = dtm.addDataType(test_struct, DataTypeConflictHandler.REPLACE_HANDLER)

        # Save data structure to struct class
        struct.data_structure = test_struct
        struct.data_structure_name = test_struct.getName()

    except:
        print('\t\t[x] Could not create custom data structure for ' + struct.name)
        return 0

    # Normal return - all is good :)
    return 1




# Find where structs are put into local variables and assign the correct custom Ghidra data structure
# Returns 1 on successful assignment, 0 if not
def assignStructs(struct, call, dataTypeManager):

    # Get CALL runtime.newobject() instructtion and function associated
    instr = listing.getInstructionAt(call)
    func = listing.getFunctionContaining(instr.getAddress())

    # Get something that will get the stack depth (for finding local variable)
    callDepther = ghidra.app.cmd.function.CallDepthChangeInfo(func)

    try:
        # Go through instructions to see where newObject may be assigned to
        while True:
            # If its a MOV instruction...
            if instr.getMnemonicString() == 'MOV':
                # And if the second operand is the _AX register...
                if instr.getDefaultOperandRepresentation(1) == REG_AX:
                    # And if the first operand is a local variable...
                    if 'SP + ' in instr.getDefaultOperandRepresentation(0):

                        # Get the variable offset and stack depth at instruction
                        var_offset = int(str(instr.getDefaultOperandRepresentation(0)).split('+')[-1].strip(' ').strip(']'), 16)
                        depth = callDepther.getDepth(instr.getAddress())

                        # Calculate 'local_xxx' value from depth and offset
                        var_val = (-1 * depth) - var_offset
                        
                        # For all local variables...
                        for var in func.getLocalVariables():
                            # If the offset and variable name match...
                            if var.getName().endswith('_' + hex(var_val).split('x')[-1]):

                                # Create pointer to correct data structure and assign it
                                pnt = dataTypeManager.getPointer(struct.data_structure)
                                var.setDataType(pnt, var.getSource())
                    return 1
                
                # If the runtime.newobject() register gets overwritten...
                elif instr.getDefaultOperandRepresentation(0) == REG_AX:
                    # Oh no, can't assign custom data structure :(
                    return 0
                
                # Iterate to next instruction
                else:
                    instr = instr.getNext()
            
            # Iterate to next instruction
            else:
                instr = instr.getNext()
    
    except:
        print('\t\t[x] Could not assign custom data structure to ' + struct.name)
        return 0

''' End Data Structure section '''





''' This is the good stuff '''

# main func for testing
def detect():

    # Variables to use...
    call_newobj = {}    # Dict of all calls to runtime.newobject(), holds struct definition address and address of call
    structs = []        # List of all struct definitions

    # Get addresses of all newobject() calls and structs associated
    call_newobj = findAllNewObject()

    # Parse all found structs for field names
    structs = getStructs(call_newobj)

    # Get all names of structs
    getNames(structs)

    # Get all fields in structs
    getFields(structs)

    # Create dict of struct.base_address -> struct
    struct_addresses = createStructAddressDict(structs)

    # Associate calls to new object with the structs defined for them
    struct_calls = associate(call_newobj, struct_addresses)


    return structs, struct_calls


# Add type definition where the struct is defined
def commentTypeSource(structs):

    print
    print('[+] Commenting all struct definitions...')

    cnt = 0

    # For all structs...
    for struct in structs:

        # Start definition with struct name
        typeDef = 'type ' + struct.name + ' struct {\n'

        # Add all fields
        for field in struct.fields:
            typeDef += '\t' + field.name + ' ' + types[field.type] + '\n'
        
        # Close it
        typeDef += '}'

        # Set the comment
        setCommentPRE(struct.base_address, typeDef)
        cnt += 1
    
    # Print info message
    print('\t[-] ' + str(cnt) + ' struct definitions commented')

    return

        


# Set comments for struct inits and read/write locations
def markup(structs, struct_calls):

    reads = []
    writes = []

    # Clear all comments
    # TODO : Remove this functionality after testing
    # clearAllComments()

    # Set PRE Comments for all runtime.newobject() calls with struct names
    markupNewObjCalls(structs, struct_calls)


    # Start identifying read/write locations
    reads, writes = findWhereSaved(struct_calls)

    # Comment struct definition where defined
    commentTypeSource(structs)

    return


# Create Structure Data Types in Ghidra for all Structs
def defineAndAssignStructs(structs, struct_calls):

    print
    print('[+] Defining and assigning custom data structures')
    dataTypeManager = currentProgram.getDataTypeManager()
    
    # Create data type category to hold all custom data structures
    category_path_string = 'go_restruct'
    category = dataTypeManager.getRootCategory()
    cat_path = category.createCategory(category_path_string).getCategoryPath()

    cnt = 0
    # For all structs...
    for struct in structs:

        # if 'test' in struct.name:

        # Create custom data structures in Ghidra
        cnt += createDataStructure(struct, dataTypeManager, cat_path)
    
    print('\t[-] ' + str(cnt) + ' custom data structures created')


    cnt = 0
    # For all calls to runtime.newobject()...
    for call in struct_calls:
        # If there is a custom Ghidra data structure associated...
        if struct_calls[call].data_structure is not None:
            # Assign data structure to Ghidra variable
            cnt += assignStructs(struct_calls[call], call, dataTypeManager)
    
    print('\t[-] ' + str(cnt) + ' data structures assigned')



def main():
    print('Hello world!')

    # Get all structs
    structs, struct_calls = detect()

    # Markup struct creation & read/write with comments (assembly view)
    markup(structs, struct_calls)

    # Assign custom data structure to struct variable (decompiled view)
    defineAndAssignStructs(structs, struct_calls)

    # Print all structs to a text file
    # saveStructs(structs)


# Define some global variables
def init():
    global types                # Holds all Kinds of Go
    global POINTER_SIZE_BYTES   # Holds binary 32/64 bit value
    global POINTER_SIZE_BITS    # See above
    global REG_AX               # Holds EAX/RAX register depending on 32/64
    global type_lens

    # Ghidra API values
    global listing
    
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

    # Set pointer sizes
    POINTER_SIZE_BYTES = currentProgram.getDefaultPointerSize()
    POINTER_SIZE_BITS = 8 * POINTER_SIZE_BYTES
    
    # Set for 32-bit
    REG_AX = 'EAX'
    # Alter if 64-bit
    if POINTER_SIZE_BYTES == 8:
        REG_AX = 'RAX'
    

    # Corralate Ghidra data types to Go kinds
    type_lens = {
        'Invalid'       : 'null',
        'Bool'          : 1,
        'Int'           : POINTER_SIZE_BYTES,
        'Int8'          : 1,
        'Int16'         : 2,
        'Int32'         : 4,
        'Int64'         : 8,
        'Uint'          : POINTER_SIZE_BYTES,
        'Uint8'         : 1,
        'Uint16'        : 2,
        'Uint32'        : 4,
        'Uint64'        : 8,
        'Uintptr'       : 1,
        'Float32'       : 4,
        'Float64'       : 8,
        'Complex64'     : 8,
        'Complex128'    : 16,
        'Array'         : 1,
        'Chan'          : 1,
        'Func'          : 1,
        'Interface'     : 1,
        'Map'           : 1,
        'Pointer'       : POINTER_SIZE_BYTES,
        'Slice'         : 1,
        'String'        : 2,
        'Struct'        : 1,
        'UnsafePointer' : POINTER_SIZE_BYTES,
    }

    listing = currentProgram.getListing()

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
