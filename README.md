# go_restruct

Go ReStruct is a Ghidra plugin for struct detection, commenting, and creating custom data structures within stripped Go binaries.



This is a practicum project for Georgia Tech's CS 6727 Cybersecurity Practicum.




## How to Run
Go ReStruct does require a few scripts to be run prior, mainly for determining function names.
First step is to run the standard Ghidra auto-analysis scripts when creating a new project.

[advanced-threat-research/GhidraScripts](https://github.com/advanced-threat-research/GhidraScripts) is the recommended set of scripts to run, with the most useful being "GolangFunctionRecovery.java". Although it is recommended to run the entire set of scripts. This should be run prior to "go_restruct.py".

For the most benefit in custom data structure creation, copy the "generic_clib-64/stdint.h" & "generic_clib-64/types.h" into the project's Data Type Manager. ***insert pictures here***

Lastly, the Go ReStruct script can be run. It should be under the "capstone" folder, because I forgot to change that.




## Limitations

Currently, Go ReStruct is configured for 64-bit stripped Go binaries. There is some underlying support for 32-bit binaries, but it cannot be garuanteed.

It has been tested most thoroughly with binaries compiled with the "-s -w" flags.





Looking for useful tips on the Ghidra API in Python?
[No problem!](https://github.com/matthewlacorte/go_restruct/blob/main/useful.md)
