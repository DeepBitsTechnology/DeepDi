## DeepDi API

`DeepDiCore.so` can be directly loaded by Python via `import DeepDiCore`. 

#### DeepDiCore.Disassembler(key: str, gpu: bool)
Initializes a DeepDi instance. 
Note: please do not create multiple instances.

You can obtain a key for free at https://www.deepbits.com/deepdi.html.

#### Disassemble(code: bytes, is_x64: bool)
Disassemble the given raw bytes. Users are responsible for controlling how many bytes (batch size) are fed into DeepDi. 
GPU may run out of memory if the size is too big, and run slowly if the size is too small.

#### GetInstructionProb()
Return a NumPy array of size N (the length of the raw bytes). 
Each item in the array represents the probability of the corresponding byte being the first byte of an instruction. 
We typically pick 0.5 as the threshold. 

#### GetInstructionData()
Return a NumPy array of size \[N x 4\]. Each row is a (opcode, ModRM, SIB, REX) tuple. 

#### GetInstructionLength()
Return a NumPy array of size N. 

Note that DeepDi returns a superset of disassembly (each byte is treated as the starting point of an instruction). 
Users may want to use the following code to extract the information of "true" instructions:

```python
pred = disasm.GetInstructionProb() >= 0.5
instruction_data = disasm.GetInstructionData()[pred]
instruction_length = disasm.GetInstructionLength()[pred]
```

#### GetFunction()
Return a NumPy array of size N. This function is similar to `GetInstructionProb()`, but instead of returning an array of probabilities, it returns an array of boolean, so there is no need to check the result against a threshold. 

#### Sync()
Call `cudaStreamSynchronize()`.