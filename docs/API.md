
# DeepDi API

API document for DeepDi (DD).


## Prerequisite
The APIs are declared in `dd.h`.

## APIs

### Initialize
Call `Initialize("YOUR_KEY_HERE")` first to initialize data and load models.

### Release

`Release()` offloads models and frees memory.

### Open

`Open(binary_path)` returns a `FileData` structure which contains section information.

### FileData::Disassemble
`FileData::Disassemble(start, end, return_string)` takes the memory region (**virtual address**, which can be found in `FileData::sections`) to disassemble and returns `DisassemblyResult`. If `return_string` is `true`, the `disassembly_text` field contains instruction strings; otherwise the `disassembly` field is filled. Note that the address of the next instruction does not guarantee to be the address of the current instruction plus the instruction length, or in other words, instructions may overlap. 

If `[start, end)` contains more than one section, only the first section is taken into account.

## Compilation

To use DD APIs, include `dd.h` and link your program with `DeepDi.lib`. For the demo version, only x64 version of DeepDi.dll is provided.

## Example Program
The following program gives an basic idea of how to use DD APIs.

```c++
#include "dd.h"
#include <windows.h>
#pragma comment(lib, "DeepDi.lib")

int main(int argc, char* argv[])
{
	constexpr int batch_size = 1024 * 128;
	try
	{
        dd::Initialize("YOUR_KEY_HERE");
        for (int i = 1; i < argc; ++i)
        {
            auto file_data = dd::Open(argv[i]);
            for (auto& section : file_data.sections)
            {
                if (!section.executable) continue;

                for (auto addr = section.start; addr < section.end; addr += batch_size)
                {
                    // Get instruction meta data
                    auto result = file_data.Disassemble(addr, addr + batch_size, false);
                    for (const auto& [inst, addr] : result.disassembly)
                    {
                        auto mnemonic = inst.mnemonic;
                        for (const auto& operand : inst.operands)
                        {
                            if (operand.type == dd::OperandType::UNUSED) 
                                break;
                            if (operand.type == dd::OperandType::REGISTER)
                            {
                                auto reg = operand.reg;
                            }
                            else if (operand.type == dd::OperandType::MEM)
                            {
                                auto base_reg = operand.mem.base;
                                if (base_reg != dd::Register::NONE)
                                {
                                    // 
                                }
                                auto index_reg = operand.mem.index;
                                if (index_reg != dd::Register::NONE)
                                {
                                    // 
                                }
                            }
                        }
                    }

                    // Or, you can get instruction text
                    auto text_result = file_data.Disassemble(addr, addr + batch_size, true);
                    for (const auto& [inst, addr] : text_result.disassembly_text)
                    {
                        printf("%llx: %s\n", addr, inst.c_str());
                    }
                }
            }
        }
    }
	catch (const std::exception& e)
	{
		printf("%s\n", e.what());
	}
}
```

And Python example:

```python
import DD

DD.Initialize(b'YOUR_KEY_HERE')
batch_size = 1024 * 128
with DD.Open(b'FILE_PATH') as file_data:
    for sec in file_data.sections.iter(DD.Section):
        if not sec.executable:
            continue
        print(sec.name)
        for sec_addr in range(sec.start, sec.end, batch_size):
            text_result = file_data.disassemble(sec_addr, sec_addr + batch_size, False)
            for data in text_result.disassembly.iter(DD.Disassembly):
                length = data.instruction.length
                address = data.address
                print(length, address)
print()
```
