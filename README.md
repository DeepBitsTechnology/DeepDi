# DeepDi: A Fast and Accurate Disassembler for Binary Code AI

Disassembly is the cornerstone of many cybersecurity solutions (vulnerability search, malware classification, etc.). Deepbits leverages the recent advance in deep learning to develop **DeepDi** , a fast and accurate disassembler. It is comparable or superior to the state-of-the-art disassemblers in terms of accuracy, and is robust against unseen compilers and platforms, obfuscated binaries, and adversarial attacks. Its CPU version is eight times faster than IDA Pro, and its GPU version is 100 times faster.

# Features

* Fast and accurate disassembly.
* Obfuscation resilient.
* GPU acceleration
* Standalone library, easy to integrate.
* Flexible APIs for integration and extension
* Produce disassembly instructions and function boundaries.
* Predictable disassembly performance, no slow down while processing big files.
* Multiple choices on memory/CPU/GPU usage.
* Native support for Windows and Linux.
* Multi-architectures support.
* x86/arm..more to come...

# System Requirements


| DeepDi | Memory | Operating System | Software |
| --- | --- | --- | --- |
| CPU Version | 200Mb+ | Win 7 +/ Ubuntu 16.04+ | |
| GPU Version | 200Mb+ |Win 7 +/ Ubuntu 16.04+ | Cuda 11 |

# Performance



![performance evaluation](https://www.deepbitstech.com/assets/img/performance.png)





# Usecases
## Use Case 1: Runtime disassembler for end point antivirus software

The end point antivirus software usually uploads the suspicious samples back to cloud server for further analysis. DeepDi can be used by end point antivirus software to analyze suspicious samples in real time. So that it can reduce the workload of cloud server and the response time to new threats.

## Use Case 2: Quick memory dump analysis for cloud Virtual Machines##

The virtual machines on the clouds are potentially to be infected by various malware, e.g., cryptocurrency mining malware. With DeepDi, it is possible to identify those malware timely by scanning the memory dump of virtual machines.

# How to use DeepDi?

## Get a key from [DeepDi official site](https://www.deepbitstech.com/deepdi.html ).


## API 

please locate ./docs/API.md for details.

## IDA/BinaryNinja/Ghidra Plugins

The plugins are open sourced and can be found at https://github.com/DeepBitsTechnology.

### IDA Plugin

https://github.com/DeepBitsTechnology/DeepDiIDAPlugin

### BinaryNinja Plugin

Under development...

### Ghidra Plugin

Under development...

# Contact Us

If you have any questions, please reach us via https://www.deepbitstech.com/contact.html
