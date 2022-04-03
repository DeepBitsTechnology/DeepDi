import DeepDiCore
import numpy as np
from elftools.common.exceptions import ELFError
from elftools.elf.constants import SH_FLAGS
from elftools.elf.elffile import ELFFile
from pefile import PE
import argparse


class DeepDi:
    def __init__(self, key, gpu, batch_size):
        self.disasm = DeepDiCore.Disassembler(key, gpu)
        self.batch_size = batch_size

    def disassemble(self, path):
        try:
            code, code_addr, x64 = _get_elf_code(path)
        except ELFError:
            code, code_addr, x64 = _get_pe_code(path)

        # construct address mapping from code offset to virtual address
        addr_mapping = np.empty(len(code), dtype=np.uint64)
        cur_idx = 0
        for addr, length in code_addr:
            addr_mapping[cur_idx:cur_idx + length] = np.arange(start=addr, stop=addr + length, step=1, dtype=np.int64)
            cur_idx += length

        for i in range(0, len(code), self.batch_size):
            self.disasm.Disassemble(code[i:i+self.batch_size], x64)
            inst_pred = self.disasm.GetInstructionProb() >= 0.5
            func_pred = self.disasm.GetFunction()
            m = addr_mapping[i:i+self.batch_size]
            inst_addr = m[inst_pred]
            func_addr = m[func_pred]
            yield inst_addr, func_addr


def _get_elf_code(path):
    with open(path, 'rb') as f:
        elf = ELFFile(f)
        is_x64 = elf.elfclass == 64
        machine = elf['e_machine']
        assert machine == 'EM_386' or machine == 'EM_X86_64'

        image_base = 0
        for segment in elf.iter_segments():
            if segment['p_type'] == 'PT_LOAD':
                image_base = segment['p_paddr']
                break

        code_data = []
        code_addr = []
        for section in elf.iter_sections():
            if not (section['sh_flags'] & SH_FLAGS.SHF_ALLOC) or section.data_size == 0:
                continue

            if section['sh_flags'] & SH_FLAGS.SHF_EXECINSTR:
                code_data.append(section.data())
                code_addr.append((section['sh_addr'] - image_base, len(code_data[-1])))
        return b''.join(code_data), code_addr, is_x64


def _get_pe_code(path):
    pe = PE(path, fast_load=True)
    code_data = []
    code_addr = []
    try:
        if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) >= 15:
            dot_net = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
            if dot_net.VirtualAddress != 0 or dot_net.Size != 0:
                raise RuntimeError('.net files are not supported')

        x86 = pe.FILE_HEADER.IMAGE_FILE_32BIT_MACHINE
        for section in pe.sections:
            if not section.IMAGE_SCN_MEM_EXECUTE:
                continue
            sec_data = section.get_data()
            code_data.append(sec_data)
            sec_addr = section.VirtualAddress
            code_addr.append((sec_addr, len(sec_data)))
        return b''.join(code_data), code_addr, not x86
    finally:
        pe.close()


def example(key, gpu, path):
    deepdi = DeepDi(key, gpu, 1024 * 512)
    with open(f'{path}_inst.txt', 'w') as f_inst, open(f'{path}_func.txt', 'w') as f_func:
        for inst_addr, func_addr in deepdi.disassemble(path):
            np.savetxt(f_inst, inst_addr, '%x')
            np.savetxt(f_func, func_addr, '%x')


def main():
    parser = argparse.ArgumentParser(description='DeepDi example')
    parser.add_argument('--key', help='DeepDi key', required=True)
    parser.add_argument('--gpu', action='store_true', help='Enable GPU acceleration')
    parser.add_argument('--path', help='Path to the binary to disassemble', required=True)
    args = parser.parse_args()
    example(args.key, args.gpu, args.path)


if __name__ == '__main__':
    main()
