//This is deepdi plugin for Ghidra.
//@author DeepbitsTech
//@category DeepDi
//@keybinding Ctrl-Alt-K
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.lang.InstructionBlock;
import ghidra.program.model.lang.InstructionSet;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.program.model.lang.ProgramProcessorContext;
import ghidra.program.model.mem.DumbMemBufferImpl;


import java.io.*;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
// Description


public class deepdi_plugin extends GhidraScript {
	public String binaryFile;

	public void importFunctions(String path, long base) throws Exception {
		try (var reader = Files.newBufferedReader(Paths.get(path + "_func.txt"))) {
			String line;
			while ((line = reader.readLine()) != null) {
				var laddr = Long.parseLong(line, 16) + base;
				var addr = toAddr(laddr);
				createFunction(addr, "DeepDiFunc_" + Long.toHexString(laddr));
			}
		}
	}

	public void importInstructions(String path, long base) throws Exception {
		var listing = currentProgram.getListing();
		var memory = currentProgram.getMemory();
		var list = new ArrayList<String>();
		try (var reader = Files.newBufferedReader(Paths.get(path + "_inst.txt"))) {
			String line;
			while ((line = reader.readLine()) != null) {
				list.add(line);
			}
		}
		monitor.initialize(list.size());
		monitor.setMessage("Importing instructions");
		var cnt = 0;
		for (var line : list) {
			monitor.checkCanceled();
			try {
				var addr = toAddr(Long.parseLong(line, 16) + base);
				var buf = new DumbMemBufferImpl(memory, addr);
				var context = new ProgramProcessorContext(currentProgram.getProgramContext(), addr);
				var proto = currentProgram.getLanguage().parse(buf, context, false);
				listing.createInstruction(addr, proto, buf, context);
			} catch (Exception ignored) {
			}
			cnt += 1;
			if (cnt % 10000 == 0) {
				monitor.incrementProgress(cnt);
				cnt = 0;
			}
		}
		monitor.incrementProgress(cnt);
	}

	@Override
	protected void run() throws Exception {
		var binaryFile = currentProgram.getExecutablePath();
		if (System.getProperty("os.name").toLowerCase().indexOf("win") != -1)
			binaryFile = binaryFile.substring(1);
		var base = currentProgram.getImageBase().getOffset();
		importFunctions(binaryFile, base);
		importInstructions(binaryFile, base);
	}
}
