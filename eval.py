import glob
import time

import DeepDiCore
import numpy as np
from elftools.elf.constants import SH_FLAGS
from elftools.elf.elffile import ELFFile
from pefile import PE


def get_elf_code(f):
    elf = ELFFile(f)
    is_x64 = elf.elfclass == 64
    machine = elf['e_machine']
    assert machine == 'EM_386' or machine == 'EM_X86_64'

    code_data = []
    for section in elf.iter_sections():
        if not (section['sh_flags'] & SH_FLAGS.SHF_ALLOC) or section.data_size == 0:
            continue

        if section['sh_flags'] & SH_FLAGS.SHF_EXECINSTR:
            code_data.append(section.data())
    return b''.join(code_data), is_x64


def get_pe_code(f):
    pe = PE(data=f.read(), fast_load=True)
    code_data = []
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
        return b''.join(code_data), not x86
    finally:
        pe.close()


def evaluate(batch_size=1024*512):
    disasm = DeepDiCore.Disassembler('aaf9bb2902c6d7eeaf5a8c7156ab77113a9d02db46e33edaf5f66dc53f8c7caa5c0d35a18ee8197250c06cad37eca340a47d79dee0ed266355999ec358a040f1')
    for path in glob.glob(r'DATA_PATH\**\*.npy', recursive=True):
        parse_func = get_pe_code if path[-8] == '.' else get_elf_code

        # Remove ".npy" extension
        with open(path[:-4], 'rb') as f:
            code_data, is_x64 = parse_func(f)
        inst_label, func_label = np.load(path)

        total_inst_tp = 0
        total_inst_fp = 0
        total_inst_fn = 0
        total_func_tp = 0
        total_func_fp = 0
        total_func_fn = 0
        for i in range(0, len(code_data), batch_size):
            c = code_data[i:i+batch_size]
            disasm.Disassemble(c, is_x64)
            pred = disasm.GetInstructionProb() >= 0.5
            func_pred = disasm.GetFunction()

            total_inst_tp += (pred & inst_label[i:i+batch_size]).sum()
            total_inst_fp += (pred & ~inst_label[i:i+batch_size]).sum()
            total_inst_fn += (~pred & inst_label[i:i+batch_size]).sum()

            total_func_tp += (func_pred & func_label[i:i+batch_size]).sum()
            total_func_fp += (func_pred & ~func_label[i:i+batch_size]).sum()
            total_func_fn += (~func_pred & func_label[i:i+batch_size]).sum()

        inst_precision = total_inst_tp / (total_inst_tp + total_inst_fp)
        inst_recall = total_inst_tp / (total_inst_tp + total_inst_fn)
        func_precision = total_func_tp / (total_func_tp + total_func_fp)
        func_recall = total_func_tp / (total_func_tp + total_func_fn)
        print(path[:-4])
        print('Instruction', inst_precision, inst_recall)
        print('Function', func_precision, func_recall)

    # c = code_data[:batch_size]
    # start = time.time()
    # for _ in range(100):
    #     disasm.Disassemble(c, is_x64)
    #     _ = disasm.GetInstructionProb() >= 0.5
    #     _ = disasm.GetFunction()
    # elapse = time.time() - start
    # print(f'Efficiency: {len(c) * 100 / 1024 / 1024 / elapse} MB / s')


if __name__ == '__main__':
    evaluate()
