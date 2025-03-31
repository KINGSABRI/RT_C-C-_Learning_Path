# Dynamic Link Libraries (DLLs)

This module covers Dynamic Link Libraries (DLLs) in Windows with a focus on security implications and red team applications.

## Compilation Instructions

### DLL Creation
```bash
g++ -shared -o example_dll.dll dll_creation.cpp -std=c++11

