# C/C++ Learning Path for Cybersecurity

<div align="center">
  <p><em>A comprehensive, hands-on curriculum for mastering C and C++ with a security focus</em></p>
</div>

## 📚 Introduction

This learning path is designed for cybersecurity professionals who want to develop a deep understanding of C and C++ programming. These languages are fundamental to many security applications, including:

- 🔍 Malware analysis and reverse engineering
- 🛡️ Exploit development and vulnerability research
- 🔧 Security tool development
- 💻 System-level security analysis
- 🌐 Network protocol implementation and analysis

By mastering C and C++, security professionals can better understand how software vulnerabilities occur and how to prevent, detect, and exploit them.

## 🎯 Learning Objectives

By completing this learning path, you will:

- Master C and C++ fundamentals with a security-focused approach
- Understand memory management and common vulnerabilities
- Develop practical security tools using C/C++
- Learn network programming for security applications
- Gain skills in reverse engineering and exploit development
- Understand AV/EDR evasion techniques for red team operations
- Build a portfolio of security-focused programming projects
- Implement advanced initial access and persistence mechanisms
- Create custom shellcode and payload delivery systems


## Prerequisites

Before starting Phase 3, you should have:

1. Completed Phase 1 (C Fundamentals) and Phase 2 (C++ Fundamentals)
2. Strong understanding of pointers, memory management, and functions
3. Familiarity with basic C++ syntax and features
4. Understanding of basic security concepts

## Lab Setup and Environment

### Required Applications

1. **C++ Compiler**
   - **GCC/G++** (Linux/macOS/Windows with MinGW or WSL)
     - Version 7.0+ recommended for C++17 support
     - Version 10.0+ recommended for C++20 support
   - **Clang/LLVM** (Cross-platform)
     - Version 5.0+ recommended for C++17 support
     - Version 10.0+ recommended for C++20 support
   - **Microsoft Visual C++** (Windows)
     - Visual Studio 2017+ for C++17 support
     - Visual Studio 2019+ for C++20 support

2. **Integrated Development Environment (IDE)**
   - **Visual Studio Code** (Cross-platform)
     - Extensions: C/C++, C++ Intellisense, CMake Tools
   - **Visual Studio** (Windows)

3. **Build Systems**
   - **CMake** (Cross-platform, recommended)
   - **Make** (Linux/macOS)
   - **Ninja** (Cross-platform)

4. **Debugging Tools**
   - **GDB** (GNU Debugger) for Linux/macOS/Windows with MinGW
   - **LLDB** for macOS and systems using Clang
   - **Visual Studio Debugger** for Windows
   - **Valgrind** for memory leak detection (Linux)
   - **AddressSanitizer** for memory error detection

5. **Security Analysis Tools**
   - **Clang Static Analyzer**
   - **Cppcheck**
   - **SonarQube** or **SonarLint**
   - **Flawfinder**

6. **Version Control**
   - **Git**
   - **GitHub Desktop** or **GitKraken** (optional GUI clients)

### Installation Instructions
#### Windows

1. **Install the MinGW-w64 / VS_BuildTools toolchain**:

Install VS_BuildTools,  [Visual Studio website](https://visualstudio.microsoft.com/downloads/?q=build+tools).



Install [MSYS2](https://www.msys2.org/) and follow the instructions to set up the MinGW-w64 environment.

- Use "MSYS2 MinGW 64-bit" shortcut from the Start menu
- This ensures the PATH is set correctly for the MinGW compilers
  - Add `C:\msys64\mingw64\bin` path to your system PATH variable.


1. **Update MSYS2 packages**:

Open **MSYS2 MINGW64** shell and run:


```shellscript
pacman -Syu
```

```shellscript
# For 64-bit development
pacman -S mingw-w64-x86_64-toolchain // Choose the default options (all packages)
```

**For additional libraries and tools**
```
pacman -S mingw-w64-x86_64-cmake
pacman -S mingw-w64-x86_64-ninja
pacman -S mingw-w64-x86_64-gdb
```
3. **Install additional libraries needed for the project**:

```shellscript
# For network programming
pacman -S mingw-w64-x86_64-winsock

# For packet capture (Phase 5)
pacman -S mingw-w64-x86_64-winpcap
# or
pacman -S mingw-w64-x86_64-npcap
```

### Compiling Files by Phase

**Phase 1: C Fundamentals**

Navigate to the Phase 1 directory and compile the C files:

```shellscript
# Navigate to the project directory
cd /c/path/to/C-CPP-Learning-Path/Phase1-C-Fundamentals

# Compile a specific file (e.g., hello_security.c)
cd 01-HelloSecurity
gcc hello_security.c -o hello_security.exe

# Run the compiled program
./hello_security.exe

# Compile with turning overflow warning off 
gcc data_types.c -o data_types.exe -Wno-overflow


# Compile with warnings and security flags
gcc -Wall -Wextra -Werror -fstack-protector-all -o hello_security.exe hello_security.c
```

**Phase 2: Intermediate C**

```shellscript
# Navigate to the directory
cd /c/path/to/C-CPP-Learning-Path/Phase2-Intermediate-C

# Compile structures example
cd 01-Structures
gcc structures.c -o structures.exe

# Compile file operations example
cd ../02-FileOperations
gcc file_operations.c -o file_operations.exe

# Compile memory scanner (may need additional flags)
cd ../04-MemoryScanner
gcc memory_scanner.c -o memory_scanner.exe
```

**Phase 3: C++ Introduction**

Switch to g++ for C++ files:

```shellscript
# Navigate to the directory
cd /c/path/to/C-CPP-Learning-Path/Phase3-CPP-Introduction

# Compile C++ basics
cd 01-CPP-Basics
g++ -std=c++17 cpp_basics.cpp -o cpp_basics.exe

# Compile STL examples
cd ../02-STL
g++ -std=c++17 stl_basics.cpp -o stl_basics.exe

# Compile password manager
cd ../03-PasswordManager
g++ -std=c++17 password_manager_simple.cpp -o password_manager.exe

# Compile packet analyzer
cd ../04-PacketAnalyzer
g++ -std=c++17 packet_analyzer_simple.cpp -o packet_analyzer.exe
```

**Phase 4: Advanced C++**

```shellscript
# Navigate to the directory
cd /c/path/to/C-CPP-Learning-Path/Phase4-Advanced-CPP

# Compile templates example
cd 01-Templates
g++ -std=c++17 templates.cpp -o templates.exe

# Compile exception handling
cd ../02-ExceptionHandling
g++ -std=c++17 exception_handling.cpp -o exception_handling.exe

# Compile smart pointers example
cd ../03-SmartPointers
g++ -std=c++17 smart_pointers.cpp -o smart_pointers.exe

# Compile thread safety example (needs pthread)
cd ../04-ThreadSafety
g++ -std=c++17 thread_safety.cpp -o thread_safety.exe -pthread
```

**Phase 5: Network Programming**

Network programming requires Winsock libraries:

```shellscript
# Navigate to the directory
cd /c/path/to/C-CPP-Learning-Path/Phase5-Network-Programming

# Compile TCP server
cd 01-Socket-Programming
g++ -std=c++17 tcp_server.cpp -o tcp_server.exe -lws2_32 -pthread

# Compile TCP client
g++ -std=c++17 tcp_client.cpp -o tcp_client.exe -lws2_32

# Compile UDP server
g++ -std=c++17 udp_server.cpp -o udp_server.exe -lws2_32

# Compile DNS resolver
cd ../02-Network-Protocols
g++ -std=c++17 dns_resolver.cpp -o dns_resolver.exe -lws2_32

# Compile packet analyzer (requires WinPcap/Npcap)
cd ../03-Packet-Capture
g++ -std=c++17 pcap_analyzer.cpp -o pcap_analyzer.exe -lwpcap -lpacket
```

**Phase 6: Advanced Memory Management**

```shellscript
# Navigate to the directory
cd /c/path/to/C-CPP-Learning-Path/Phase6-Advanced-Memory-Management

# Compile custom allocator
cd 01-Memory-Allocation
g++ -std=c++17 custom_allocator.cpp -o custom_allocator.exe

# Compile heap spray example
cd ../02-Memory-Manipulation
g++ -std=c++17 heap_spray.cpp -o heap_spray.exe

# Compile DLL injection (requires Windows API)
cd ../03-Process-Memory
g++ -std=c++17 dll_injection.cpp -o dll_injection.exe

# Compile shellcode runner
cd ../04-Shellcode-Execution
g++ -std=c++17 shellcode_runner.cpp -o shellcode_runner.exe
```

**Phase 7: Windows API Programming**

Windows API programming requires additional libraries:

```shellscript
# Navigate to the directory
cd /c/path/to/C-CPP-Learning-Path/Phase7-Windows-API-Programming

# Compile registry operations
cd 01-Windows-Fundamentals
g++ -std=c++17 registry_operations.cpp -o registry_operations.exe -ladvapi32

# Compile thread management
cd ../02-Process-Thread-Management
g++ -std=c++17 thread_management.cpp -o thread_management.exe -lkernel32

# Compile DLL creation
cd ../03-Dynamic-Link-Libraries
g++ -std=c++17 -shared -o example_dll.dll dll_creation.cpp -Wl,--out-implib,libexample.a

# Compile API hooking example
cd ../04-API-Hooking
g++ -std=c++17 inline_hooking.cpp -o inline_hooking.exe
```

**Phase 8: Advanced Topics (AV/EDR Evasion)**

```shellscript
# Navigate to the directory
cd /c/path/to/C-CPP-Learning-Path/Phase8-Advanced-Topics

# Compile string obfuscation
cd 01-AV-EDR-Evasion
g++ -std=c++17 string_obfuscation.cpp -o string_obfuscation.exe

# Compile dynamic analysis
cd ../02-Malware-Analysis
g++ -std=c++17 dynamic_analysis.cpp -o dynamic_analysis.exe

# Compile format string example
cd ../03-Exploit-Development
g++ -std=c++17 format_string.cpp -o format_string.exe
```

**Using CMake with MSYS2**

For more complex projects, you can use CMake:

```shellscript
# Navigate to a project directory
cd /c/path/to/C-CPP-Learning-Path/Phase4-Advanced-CPP

# Create build directory
mkdir build
cd build

# Generate Makefiles
cmake .. -G "MSYS Makefiles"

# Build the project
cmake --build .
```

### Compilation Tips for MSYS2

1. **Use the correct shell**: Always use the "MSYS2 MinGW 64-bit" shell for compilation, not the regular MSYS2 shell.
2. **Path conversion**: MSYS2 automatically converts Unix-style paths to Windows paths. If you have issues, use explicit Windows paths with forward slashes:

```shellscript
gcc C:/path/to/file.c -o output.exe
```

3. **Common GCC flags**:

- `-Wall -Wextra`: Enable important warnings
- `-Werror`: Treat warnings as errors
- `-std=c++17`: Use C++17 standard (for C++ files)
- `-g`: Add debugging information
- `-O2`: Optimize code (level 2)
- `-fstack-protector-all`: Stack protection
- `-D_FORTIFY_SOURCE=2`: Additional security checks
- `Woverflow`: Disable overflow warnings (if needed)
- `-fPIC`: Position-independent code (for shared libraries)
- `-shared`: Create a shared library

4. **Windows-specific libraries**:

- `-lws2_32`: Winsock (network programming)
- `-ladvapi32`: Advanced Windows APIs
- `-luser32`: User interface APIs
- `-lkernel32`: Core Windows APIs
- `-lpsapi`: Process Status API

5. **Handling spaces in paths**: If your path contains spaces, use quotes:

```shellscript
gcc "C:/My Projects/file.c" -o output.exe
```


### Troubleshooting MSYS2 Compilation Issues

1. **"Command not found"**: Ensure you're using the MinGW shell and the toolchain is installed:

```shellscript
which gcc
which g++
```


2. **Missing libraries**: Install required packages:

```shellscript
pacman -S mingw-w64-x86_64-<package-name>
```


3. **Path issues**: Check your PATH environment variable:

```shellscript
echo $PATH
```


4. **DLL not found when running**: Add MinGW bin directory to Windows PATH or copy required DLLs to the same directory as your executable.
5. **Permission denied**: Check file permissions or try running as administrator.




## 🗂️ Project Structure

The project is organized into eight progressive phases, each building upon the previous:

### Phase 1: C Fundamentals
*Foundation concepts with security context*
- Basic syntax and program structure
- Data types and memory representation
- Control flow and decision making
- Arrays, strings, and buffer management
- Pointers and memory addressing
- Practical exercises: Password checker, Buffer overflow demo

### Phase 2: Intermediate C
*Deeper C concepts with security applications*
- Structures and complex data types
- File operations and security considerations
- Advanced memory management
- Practical exercise: Memory scanner, File integrity checker

### Phase 3: C++ Introduction
*Transitioning to C++ with security benefits*
- C++ basics and object-oriented concepts
- Standard Template Library (STL)
- Practical exercises: Password manager, Packet analyzer

### Phase 4: Advanced C++
*Modern C++ features for secure programming*
- Templates and generic programming
- Exception handling for robust applications
- Smart pointers and memory safety
- Thread safety and synchronization

### Phase 5: Network Programming
*Network security applications*
- Socket programming
- Protocol implementation
- Network tools development
- Secure communication
- **Red Team Focus**: Custom C2 channel implementation
- **Red Team Focus**: DNS tunneling and exfiltration techniques

### Phase 6: Advanced Memory Management
*Memory manipulation and security*
- Memory allocation and deallocation
- Heap and stack memory management
- Memory corruption vulnerabilities
- Binary analysis and reverse engineering
- **Red Team Focus**: Process injection techniques
- **Red Team Focus**: DLL proxying

### Phase 7: Windows API Programming
*Windows API for security applications*
- Windows API fundamentals
- Process and thread management
- Dynamic-link libraries (DLLs)
- API hooking and unhooking
- **Red Team Focus**: Windows API internals
- **Red Team Focus**: Direct syscall implementation
- **Red Team Focus**: In-memory exploitation techniques
- **Red Team Focus**: Shellcode development and optimization

### Phase 8: AV/EDR Evasion
*Understanding detection and evasion (for red team operations)*
- Detection methods
- String obfuscation techniques
- Code injection methods
- Process hollowing
- Sandbox evasion techniques
- Custom loaders and shellcode
- **Red Team Focus**: AMSI bypass techniques
- **Red Team Focus**: ETW/Sysmon evasion
- **Red Team Focus**: Living-off-the-land binary (LOLBin) utilization
- **Red Team Focus**: Custom loader development
- **Red Team Focus**: Code signing and certificate bypasses

## 🚀 How to Use This Learning Path

### Prerequisites
- Basic programming knowledge in any language
- Understanding of computer architecture concepts
- Linux/Unix command line familiarity (recommended)
- Development environment with GCC/G++ or equivalent compiler
- Basic understanding of cybersecurity concepts

### Setup Instructions
1. Clone this repository to your local machine
2. Ensure you have a C/C++ compiler installed (GCC/G++ recommended)
3. For Windows users, consider using WSL or MinGW
4. Each phase has its own directory with code examples and exercises
5. For red team exercises, set up isolated virtual environments

### Learning Methodology
1. **Sequential Progression**: Work through phases in order, as each builds on previous concepts
2. **Read, Understand, Modify, Create**:
   - Study the provided code examples
   - Ensure you understand the concepts
   - Modify the examples to experiment
   - Create your own implementations

3. **Practical Application**:
   - Complete all exercises in each phase
   - Build the suggested projects
   - Extend projects with your own features

4. **Documentation**:
   - Read the README in each phase directory
   - Review code comments for detailed explanations
   - Consult additional resources when needed

5. **Testing and Experimentation**:
   - Test code in different environments
   - Experiment with breaking/fixing code
   - Analyze security implications

## 🏃‍♂️ Accelerated Study Plan

This accelerated plan is designed for those who want to complete the course efficiently while focusing on red team skills.

### Prerequisites Assessment (1-2 days)
- Assess your C/C++ knowledge with the provided self-assessment quiz
- Review basic programming concepts if needed
- Set up your development environment

### Phase 1-2: C Foundations (1 week)
- **Days 1-2**: Complete Phase 1 core concepts (syntax, data types, control flow)
- **Days 3-4**: Focus on pointers, memory management, and buffer operations
- **Days 5-7**: Complete Phase 2 with emphasis on memory manipulation
- **Weekend Project**: Build the Memory Scanner tool

### Phase 3-4: C++ Essentials (1 week)
- **Days 1-2**: Learn C++ basics and object-oriented principles
- **Days 3-4**: Master STL containers and algorithms
- **Days 5-7**: Focus on smart pointers and memory safety
- **Weekend Project**: Enhance the Packet Analyzer with custom protocol support

### Phase 5: Network Programming (5 days)
- **Days 1-2**: Socket programming fundamentals
- **Days 3-5**: Build a basic C2 channel implementation
- **Key Focus**: Data exfiltration techniques

### Phase 6: Reverse Engineering Essentials (5 days)
- **Days 1-2**: Binary analysis and disassembly
- **Days 3-5**: API hooking and security control identification
- **Key Focus**: DLL proxying techniques

### Phase 7: Exploit Development (1 week)
- **Days 1-2**: Vulnerability types and exploitation basics
- **Days 3-4**: In-memory exploitation techniques
- **Days 5-7**: Shellcode development and optimization
- **Weekend Project**: Create a custom shellcode injector

### Phase 8: AV/EDR Evasion (1 week)
- **Days 1-2**: Understanding detection methods
- **Days 3-4**: String obfuscation and code injection
- **Days 5-7**: Advanced evasion techniques
- **Final Project**: Develop a custom loader with multiple evasion techniques

### Total Duration: 5-6 weeks (intensive study)

#### Efficiency Tips:
1. **Focus on practical exercises** over theoretical content
2. **Skip redundant concepts** if you're already familiar with them
3. **Prioritize red team-focused modules** if that's your primary goal
4. **Build incrementally** - enhance previous projects rather than starting from scratch
5. **Form study groups** to discuss concepts and review code
6. **Set daily goals** and track your progress

## 🔴 Red Team Focus Areas

For red teamers specifically interested in AV/EDR evasion and initial access:

### Essential Skills to Master
1. **Memory Manipulation**
   - Direct memory access and modification
   - Process memory layout understanding
   - Heap and stack manipulation

2. **Code Injection Techniques**
   - Remote process injection
   - Reflective DLL loading
   - Process hollowing and doppelgänging
   - Thread execution hijacking

3. **API Understanding**
   - Windows API internals
   - Direct syscall implementation
   - API hooking and unhooking

4. **Evasion Techniques**
   - String obfuscation methods
   - Control flow obfuscation
   - Anti-debugging and anti-VM techniques
   - AMSI and ETW bypass methods
   - Sandbox detection and evasion

5. **Payload Development**
   - Position-independent code
   - Shellcode optimization
   - Custom encoders and crypters
   - Staged payload delivery

### Recommended Practice Projects
1. Create a custom process injector with multiple techniques
2. Develop a reflective DLL loader with string obfuscation
3. Implement a custom C2 channel using uncommon protocols
4. Build a shellcode runner with multiple evasion techniques
5. Create a tool to bypass common EDR hooks

## ⚠️ Ethical Considerations

This learning path includes techniques that could be misused. All content is provided for **educational purposes only**. Always:

- Practice in controlled, legal environments
- Never use these skills against systems without explicit permission
- Follow responsible disclosure practices for vulnerabilities
- Adhere to applicable laws and regulations
- Maintain proper authorization for all red team activities

## 📖 Additional Resources

### General C/C++ Resources
- [C Programming Language Reference](https://en.cppreference.com/w/c)
- [C++ Reference](https://en.cppreference.com/w/cpp)
- [OWASP C-Based Toolchain Hardening Guide](https://owasp.org/www-pdf-archive/OWASP_C-based_Toolchain_Hardening.pdf)
- [Secure Coding in C and C++](https://wiki.sei.cmu.edu/confluence/display/c/SEI+CERT+C+Coding+Standard)

### Red Team Specific Resources
- [Red Team Field Manual (RTFM)](https://github.com/tanc7/hacking-books/blob/master/RTFM%20-%20Red%20Team%20Field%20Manual%20v3.pdf)
- [Windows Internals](https://docs.microsoft.com/en-us/sysinternals/resources/windows-internals)
- [Practical Malware Analysis](https://nostarch.com/malware)
- [Red Team Development and Operations](https://redteam.guide/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

## 🤝 Contributing

Contributions to improve this learning path are welcome! Please feel free to submit pull requests or open issues to suggest improvements.

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

