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