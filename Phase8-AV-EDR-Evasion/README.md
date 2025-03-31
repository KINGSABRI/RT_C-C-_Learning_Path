# Phase 8: Advanced Topics - AV/EDR Evasion

This phase covers advanced techniques for evading Antivirus (AV) and Endpoint Detection and Response (EDR) systems. These techniques are commonly used by malware and red team tools to bypass security controls.

## WARNING

The techniques demonstrated in this phase are for educational purposes only. Do not use these techniques to bypass security controls without proper authorization. Unauthorized use of these techniques may violate laws and regulations.

## Modules

### 01. Understanding Detection Mechanisms

This module covers the various detection mechanisms used by AV and EDR systems, including:

- Signature-based detection
- Heuristic-based detection
- Behavioral detection
- Machine learning-based detection
- Memory scanning
- API hooking

Files:
- `sandbox_detection.c`: Demonstrates techniques for detecting sandbox and analysis environments
- `string_obfuscation.c`: Demonstrates string obfuscation techniques for evading signature-based detection

### 02. Code Injection Techniques

This module covers various code injection techniques, including:

- Process injection
- DLL injection
- Reflective DLL injection
- Process hollowing
- Atom bombing
- Thread execution hijacking

### 03. Memory Manipulation

This module covers memory manipulation techniques, including:

- Direct syscalls
- Memory patching
- Hooking bypass
- Memory region manipulation
- Shellcode execution

### 04. Persistence Mechanisms

This module covers persistence mechanisms, including:

- Registry modifications
- Scheduled tasks
- Service creation
- WMI event subscriptions
- COM hijacking
- DLL search order hijacking

### 05. Command and Control Evasion

This module covers command and control (C2) evasion techniques, including:

- Domain fronting
- DNS tunneling
- ICMP tunneling
- Steganography
- Protocol obfuscation
- Traffic manipulation

### 06. Custom Loaders

This module covers custom loading techniques, including:

- Custom PE loaders
- Reflective loading
- Memory module loading
- Manual mapping
- PE header manipulation
- Import address table (IAT) manipulation

Files:
- `custom_pe_loader.c`: Demonstrates a custom PE loader implementation
- `reflective_dll_injection.c`: Demonstrates reflective DLL injection technique
- `memory_module_loader.c`: Demonstrates loading a DLL from memory using the MemoryModule technique

## Learning Objectives

- Understand how AV and EDR systems detect malicious code
- Learn techniques for evading detection
- Understand the limitations of evasion techniques
- Learn how to implement custom loaders and injectors
- Understand the security implications of these techniques

## Resources

- [Red Team Field Manual (RTFM)](https://www.amazon.com/Rtfm-Red-Team-Field-Manual/dp/1494295504)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Windows Internals](https://www.amazon.com/Windows-Internals-Part-architecture-management/dp/0735684189)
- [Practical Malware Analysis](https://www.amazon.com/Practical-Malware-Analysis-Hands-Dissecting/dp/1593272901)
- [The Art of Memory Forensics](https://www.amazon.com/Art-Memory-Forensics-Detecting-Malware/dp/1118825098)

