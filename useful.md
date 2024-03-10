# List of useful functions and types and all the other good stuff


### Listing
https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Listing.html

`listing = currentProgram.getListing()` will get the Listing of the binary


### Functions
https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Function.html

`func = getFirstFunction()` returns first function in program
`func = getFuncAfter(func)` can be used to iterate over all functions
`func = currentProgram.getListing().getFunctionContaining()` to get the function an address belongs to

`name = func.getName()` returns given name/label of function

`addr = func.getEntryPoint()` returns entry point address of function



### Variables
https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Variable.html

`varList = func.getAllVariables()` to get all variables within a function


### Instructions
https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Instruction.html

`ins = getFirstInstruction()` returns first instruction in program
`ins = getInstructionAfter(ins)` can be used to iterate over all instructions
`next_ins = ins.getNext()` gets next instruction

`ins.getMnemonicString()` returns the assembly instruction (ADD, CALL, JMP, etc.) used

`ins.getDefaultOperandRepresentation(x)` returns argx in instruction (RAX, RBX, etc.)



### Addresses
https://ghidra.re/ghidra_docs/api/ghidra/program/model/address/Address.html
https://ghidra.re/ghidra_docs/api/ghidra/program/model/address/AddressFactory.html

`addr = currentProgram.getAddressFactory().getAddress('0xdeadbeef')` creates address object of `0xdeadbeef`

`next = addr.add(x)` returns address x memory locations added



### Data
https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Data.html

`data = listing.getDataAt(addr)` gets data at the given address addr
`data = listing.getDataContaining(addr)` gets data that encapsulates the given address addr
`type = data.getDataType()` returns type of data
`val = data.getValue()` returns value of data


`string = ghidra.program.model.data.StringDataType()` creates DataType of string. Can be replaced with other types

`listing.clearCodeUnits(start_addr, end_addr, True)` clears all defined data in range of start_addr to end_addr


### Data Types
https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/package-summary.html

`IntegerDataType()`
`StringDataType()`


### Data Structures
https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/StructureDataType.html



### Memory Blocks
https://ghidra.re/ghidra_docs/api/ghidra/program/model/mem/MemoryBlock.html

`blocks = getMemoryBlocks()` returns all blocks of memory

`name = block.getName()` gives the names of the memory block

`addr = block.getStart()` gives the starting address of the memory block




### Miscellanious


`createLabel(addr, string, x)` creates new data of DataType at addr, with length of x

`codeUnits = listing.getCodeUnitsAt(addr)`

`executable_format = currentProgram.getExecutableFormat()` isn't really useful but dropping it anyway

`pointer_size = currentProgram.getDefaultPointerSize()` will get the default size of pointers (in bytes) for the binary



https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/RepeatableComment.html
https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/CodeUnit.html











`getInt(addr)`
`getLong(addr)` are methods