# DeepDi: A Fast and Accurate Disassembler for Binary Code AI

Disassembly is the cornerstone of many cybersecurity solutions (vulnerability search, malware classification, etc.). Deepbits leverages the recent advance in deep learning to develop **DeepDi** , a fast and accurate disassembler. It is comparable or superior to the state-of-the-art disassemblers in terms of accuracy, and is robust against unseen compilers and platforms, obfuscated binaries, and adversarial attacks. Its CPU version is two times faster than IDA Pro, and its GPU version is over 300 times faster.

This is a community edition free for non-commercial use only. 

## PUBLICATIONS
[**USENIX Security'22**] Sheng Yu, Yu Qu, Xunchao Hu, and Heng Yin, [DeepDi: Learning a Relational Graph Convolutional Network Model on Instructions for Fast and Accurate Disassembly](https://www.cs.ucr.edu/~heng/pubs/DeepDi.pdf), to appear in the 31st USENIX Security Symposium, August 2022.

## Features
* Fast and accurate x86 disassembler
* Obfuscation resilient
* GPU acceleration
* Good scalability
* Python interface
* Produce disassembly instructions and function boundaries

## Getting Started
### Requirements
1. Docker
2. DeepDi runs on most modern x86_64 machines, with optional GPU support provided via CUDA. The GPU version requires Maxwell cards and above, and the minimum required driver version for CUDA is `>=450.80.02` for Linux and `>=452.39` for Windows.

### To get started
1. Install Docker (and [NVIDIA Container Toolkit](https://github.com/NVIDIA/nvidia-docker) to pass NVIDIA GPUs to containers)
2. Clone the master branch
3. Run `docker build -t DeepDi .` (or `docker build -t DeepDi -f Dockerfile-gpu .` for GPU support).
4. Run `docker run --rm -it DeepDi`. Add `--gpus all` to the docker command line if you intend to use GPU.
5. Usage: `python3 DeepDi.py --key KEY [--gpu] --path PATH`. You can obtain a key for free at https://www.deepbits.com/deepdi#get-free-trial.

The core functionalities are provided via `DeepDiCore.so`. See [API.md](API.md) for the low-level APIs.

We also provide `DeepDi.py`, an example wrapper of the low-level APIs to extract inputs for DeepDi and return instruction and function virtual addresses. 


## Best Practices

### Reuse the `DeepDi` Instance

Instantiating `DeepDi` is expensive — it loads the neural network model and initializes the underlying `DeepDiCore.Disassembler`. Create the instance **once** and reuse it across all disassembly tasks.

**Do this:**
```python
deepdi = DeepDi(key, gpu=False, batch_size=1024 * 1024)
for path in binary_paths:
    for inst_addr, func_addr in deepdi.disassemble(path):
        ...
```

**Avoid this:**
```python
for path in binary_paths:
    deepdi = DeepDi(key, gpu=False, batch_size=1024 * 1024)  # recreated every iteration — very slow
    for inst_addr, func_addr in deepdi.disassemble(path):
        ...
```

## Contact Us
If you have any questions, please create an issue or reach us via https://www.deepbits.com/about#contact-us.
