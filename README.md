# DeepDi

DeepDi is a novel disassembler that utilizes GPU to achieve both high accuracy and high efficiency. Currently it can recover instruction and function boundaries, and return instruction metadata (`opcode`, `modrm`, `sib`, and `rex`). This binary release is built on [onnxruntime](https://github.com/microsoft/onnxruntime) and is currently only available on Windows 10 x64. Other platform supports will be released later. 

**Please unzip `dependencies.zip` in the same directory as `DeepDiCore.pyd`**.

## Hardware Requirements

This binary release requires an NVIDIA GPU with compute capability of 5.2 or above available. CPU-only inference is not supported in this release. A list of GPUs and their compute capabilities can be found at [https://developer.nvidia.com/cuda-gpus](https://developer.nvidia.com/cuda-gpus).

## Software Dependencies

This binary release is built as a Python extension. Due to the ABI compatibility issue, it strictly requires Python 3.8. It is also an x64 extension, so it will not work on x86 Windows.

Dependencies:

- Python 3.8
- CUDA 11.1
- MSVC runtime 2019 ([link](https://aka.ms/vs/16/release/vc_redist.x64.exe))
- cuDNN v8.2.4 for CUDA 11.4

Please add `cudnn\bin` to `PATH` environment variable, or put cuDNN DLLs and DeepDi in the same folder. 

If you need to run the evaluation script, please run `pip install pyelftools pefile` as well to install the dependencies. 

## DeepDi API

`DeepDiCore.pyd` can be directly loaded by Python via `import DeepDiCore`. 

#### DeepDiCore.Disassembler('key')

This call initializes a disassembler instance. Please try not to create multiple instances as it may cause extra GPU memory stress. This instance is NOT thread-safe. 

Please use this key `aaf9bb2902c6d7eeaf5a8c7156ab77113a9d02db46e33edaf5f66dc53f8c7caa5c0d35a18ee8197250c06cad37eca340a47d79dee0ed266355999ec358a040f1` for evaluation. 

#### Disassemble(code, is_x64)

Disassemble the given code. 

`code`: bytes

&nbsp;&nbsp;&nbsp;&nbsp;Users are responsible for controlling how many bytes (batch size) are fed into DeepDi. GPU may run out of memory if the size is too large, and run slowly if the size is too small. On 2080 Ti (11 GB memory), the batch size we use is 1024*512. Please refer to `get_elf_code()` and `get_pe_code()` in `eval.py` for extracting code sections. You can also feed the whole binary as input. 

`is_x64`: boolean

&nbsp;&nbsp;&nbsp;&nbsp;Whether the code is 64-bit or 32-bit. 

#### GetInstructionProb()

Return a NumPy array of size N (the given code length). Each item in the array represents the probability of the corresponding byte being the first byte of an instruction. We typically pick 0.5 as the threshold. 

#### GetInstructionData()

Return a NumPy array of size [N x 4]. Each row is a (opcode, ModRM, SIB, REX) tuple. 

#### GetInstructionLength()

Return a NumPy array of size N. 

Note that DeepDi returns a superset of disassembly (each byte is treated as the starting point of an instruction). Users may want to use the following code to extract information of "true" instructions:

```python
pred = disasm.GetInstructionProb() >= 0.5
instruction_data = disasm.GetInstructionData()[pred]
instruction_length = disasm.GetInstructionLength()[pred]
```

#### GetFunction()

Return a NumPy array of size N. This function is similar to `GetInstructionProb()`, but instead of returning an array of probabilities, it returns an array of boolean, so there is no need to check the result against a threshold. 

## Evaluation Script

The code in `eval.py` is pretty self-explanatory. It first reads the code section of the provided sample binary and feeds it into DeepDi. The script then compares the output of DeepDi with the ground truth, and prints precision, recall, and runtime efficiency. 

Please change the path on line 49 before you run the script. 

