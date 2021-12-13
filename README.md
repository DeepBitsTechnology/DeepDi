# DeepDi: A Fast and Accurate Disassembler for Binary Code AI

Disassembly is the cornerstone of many cybersecurity solutions (vulnerability search, malware classification, etc.). Deepbits leverages the recent advance in deep learning to develop **DeepDi** , a fast and accurate disassembler. It is comparable or superior to the state-of-the-art disassemblers in terms of accuracy, and is robust against unseen compilers and platforms, obfuscated binaries, and adversarial attacks. Its CPU version is eight times faster than IDA Pro, and its GPU version is 100 times faster.

## PUBLICATIONS


1.  [**USENIX Security'22**] Sheng Yu, Yu Qu, Xunchao Hu, and Heng Yin, [DeepDi: Learning a Relational Graph Convolutional Network Model on Instructions for Fast and Accurate Disassembly](https://www.cs.ucr.edu/~heng/pubs/DeepDi.pdf), to appear in the 31st USENIX Security Symposium, August 2022.


## Features

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

## System Requirements


| DeepDi | Memory | Operating System | Software |
| --- | --- | --- | --- |
| CPU Version | 200Mb+ | Win 7 +/ Ubuntu 16.04+ | |
| GPU Version | 200Mb+ |Win 7 +/ Ubuntu 16.04+ | Cuda 11 |

## Performance



![performance evaluation](https://www.deepbitstech.com/assets/img/performance.png)



Details can be found [here](https://blog.deepbitstech.com/2020/06/deepdisassembly-blazing-fast-and.html).

## How to use DeepDi?

Details can be found [here](https://deepbitstech.gitbook.io/deepdi/).

## Contact Us

If you have any questions, please reach us via https://www.deepbitstech.com/contact.html
