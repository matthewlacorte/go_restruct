#Find all calls to runtime.newobject()
#@author Matthew LaCorte
#@category Capstone
#@keybinding 
#@menupath 
#@toolbar 

import json
import time


# Error out with message
def err(msg):
    printerr(msg)
    exit(0)

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
                # print('runtime.newobject() call')

                # Look back through previous instructions to find where EAX/RAX was assigned
                for i in range(len(instructions) + 1):
                    tmpi = instructions[-1 * i]
                    if tmpi.getMnemonicString() == 'LEA':
                        # print(tmpi)
                        if tmpi.getDefaultOperandRepresentation(0) == 'RAX':
                            # Add struct address to list
                            structs.append(tmpi.getDefaultOperandRepresentation(1))

                            # Add instruction + struct to dict
                            call_newobj[str(instr.getMinAddress())] = {
                                'instruction': instr,
                                'struct': tmpi.getDefaultOperandRepresentation(1)[1:-1]
                            }

                            # found it!
                            break
                        elif tmpi.getDefaultOperandRepresentation(0) == 'EAX':
                            # Add struct address to list
                            structs.append(tmpi.getDefaultOperandRepresentation(1))
                            
                            # Add instruction + struct to dict
                            call_newobj[str(instr.getMinAddress())] = {
                                'instruction': instr,
                                'struct': tmpi.getDefaultOperandRepresentation(1)[1:-1]
                            }

                            # found it!
                            break
        
        # Get next instruction
        instr = instr.getNext()
    
    return instructions, call_newobj, structs


# Write to file
def writeToFile(call_newobj):

    tmp = []

    # For all addresses of structs...
    for key in call_newobj.keys():

        # Create dict with calling location and struct address
        tmp.append({
            'instruction': ('0x' + str(call_newobj[key]['instruction'].getMinAddress())),
            'struct': call_newobj[key]['struct']
        })

    # Write instructions/structs to file
    with open('/Users/mlc/ghidra_scripts/capstone/outputs/findAllNewObject.txt', 'w+') as f:
        f.write(json.dumps(tmp))
    
    return


# main func for testing
def main():

    # Hello info
    print('Finding all calls to runtime.newobject() and locations of structs used')


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

    # Write info to file
    writeToFile(call_newobj)


    return

# init
if __name__ == '__main__':
    start_time = time.time()
    main()
    print("--- %s seconds ---" % (time.time() - start_time))
