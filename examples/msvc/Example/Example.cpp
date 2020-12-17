// Example.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "dd.h"
#include <stdio.h>
#include <windows.h>
#pragma comment(lib, "DeepDi.lib")


int main(int argc, char* argv[])
{
    constexpr int batch_size = 1024 * 128;
    try
    {
        dd::Initialize("YOUR_KEY");
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

                    // Get instruction text
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

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
