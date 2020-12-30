import com.sun.jna.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.lang.InstructionBlock;
import ghidra.program.model.lang.InstructionSet;
import ghidra.program.model.util.CodeUnitInsertionException;


import java.io.Closeable;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
// Description

/**
 * Simple example of JNA interface mapping and usage.
 */
public class deepdi_plugin extends GhidraScript {

	public interface DDInterface extends Library {
		DDInterface INSTANCE = (DDInterface)
				Native.load("DeepDi",
						DDInterface.class);

		void Initialize(String key);

		void Release();

		void COpen(String path, FileData fileData);

		void Disassemble(FileData fileData, long start, long end, boolean returnString, DisassemblyResult result);

		void FileDataDtor(FileData fileData);

		void DisassemblyResultDtor(DisassemblyResult result);


		@Structure.FieldOrder({"sections", "internalData"})
		public static class FileData extends Structure implements Closeable {
			public Vector sections;
			public Pointer internalData;

			@Override
			public void close() {
				DDInterface.INSTANCE.FileDataDtor(this);
			}

			public static FileData open(String path) {
				var fileData = new FileData();
				DDInterface.INSTANCE.COpen(path, fileData);
				return fileData;
			}

			public DisassemblyResult disassemble(long start, long end, boolean returnString) {
				var result = new DisassemblyResult();
				DDInterface.INSTANCE.Disassemble(this, start, end, returnString, result);
				return result;
			}
		}

		@Structure.FieldOrder({"functions", "disassemblyText", "disassembly"})
		public static class DisassemblyResult extends Structure implements Closeable {
			public Vector functions;
			public Vector disassemblyText;
			public Vector disassembly;

			@Override
			public void close() {
				DDInterface.INSTANCE.DisassemblyResultDtor(this);
			}
		}

		@Structure.FieldOrder({"text", "address"})
		public static class DisassemblyText extends Structure {
			public Str text;
			public long address;

			public DisassemblyText(Pointer p) {
				super(p);
				read();
			}
		}

		@Structure.FieldOrder({"instruction", "address"})
		public static class Disassembly extends Structure {
			public Instruction instruction;
			public long address;

			public Disassembly(Pointer p) {
				super(p);
				read();
			}
		}

		@Structure.FieldOrder({"buf"})
		public static class Bxty extends Structure {
			public byte[] buf = new byte[16];
		}

		@Structure.FieldOrder({"bx", "mySize", "myRes"})
		public static class Str extends Structure {
			public Bxty bx;
			public long mySize;
			public long myRes;

			@Override
			public String toString() {
				if (myRes >= 16) {
					long addr = 0;
					for (int i = 0; i < 8; ++i) {
						addr += (bx.buf[i] & 0x000000FFL) << (i * 8);
					}
					return new Pointer(addr).getString(0, "UTF-8");
				}
				bx.buf[15] = 0;
				return new String(bx.buf, 0, (int) mySize, StandardCharsets.UTF_8);
			}
		}

		@Structure.FieldOrder({"address"})
		public static class Address extends Structure {
			public long address;
		}

		@Structure.FieldOrder({"start", "end", "offset", "name", "writable", "executable"})
		public static class Section extends Structure {
			public long start;
			public long end;
			public long offset;
			public Str name;
			public boolean writable;
			public boolean executable;

			public Section(Pointer p) {
				super(p);
				read();
			}
		}

		@Structure.FieldOrder({"base", "index"})
		public static class Memory extends Structure {
			public int base;
			public int index;
		}

		@Structure.FieldOrder({"mem"})
		public static class OperandData extends Structure {
			public Memory mem;
		}

		@Structure.FieldOrder({"data", "type", "read", "write"})
		public static class Operand extends Structure {
			public OperandData data;
			public int type;
			public boolean read;
			public boolean write;
		}

		@Structure.FieldOrder({"mnemonic", "operands", "length"})
		public static class Instruction extends Structure {
			public int mnemonic;
			public Operand[] operands = new Operand[10];
			public char length;
		}

		@Structure.FieldOrder({"myFirst", "myLast", "myEnd"})
		public static class Vector extends Structure {
			public Pointer myFirst;
			public Pointer myLast;
			public Pointer myEnd;

			public <E extends Structure> Iterable<E> iter(Class<E> cls) {
				return () -> new VectorIterator<>(cls, this);
			}
		}

		public static class VectorIterator<E extends Structure> implements Iterator<E> {
			private final Class<E> type;
			private final Vector vec;
			private long offset = 0;
			private final long length;

			public VectorIterator(Class<E> cls, Vector vec) {
				this.type = cls;
				this.vec = vec;
				this.length = Pointer.nativeValue(vec.myLast) - Pointer.nativeValue(vec.myFirst);
			}

			@Override
			public boolean hasNext() {
				return offset < length;
			}

			@Override
			public E next() {
				try {
					var n = this.type.getDeclaredConstructor(Pointer.class).newInstance(vec.myFirst.share(offset));
					this.offset += n.size();
					return n;
				} catch (Exception e) {
					throw new RuntimeException(e);
				}
			}
		}
	}

	public String binaryFile;

	public int batchSize = 1024 * 256;

	public String key = "f9fa0f00e77e30915bd6d177155896130f97305e9f9c64fb7ee68acaf9291b6b";

	protected void displayProgress(int i, int total, String str) {

	}

	public ArrayList generateFunctions() {
		println("DeepDi started...");
		ArrayList<Map<String, Long>> functions = new ArrayList<>();
		try (var fileData = DDInterface.FileData.open(binaryFile)) {
			for (var sec : fileData.sections.iter(DDInterface.Section.class)) {
				if (!sec.executable) {
					continue;
				}

				for (var addr = sec.start; addr < sec.end; addr += batchSize) {
					var textResult = fileData.disassemble(addr, addr + batchSize, false);
					for (var data : textResult.functions.iter(DDInterface.Address.class)) {

						var entryPoint = data.address;
						Map<String, Long> map = new HashMap<>() {{
							put("entry_point", entryPoint);
						}};
						functions.add(map);

					}
				}

			}
//			println("generated {} functions successfully!");
		} catch (Exception e) {
			println("Function generation failed!");
		}

		return functions;
	}

	public void importFunctions(ArrayList<Map> functions) {
//		println('Importing {} functions: '.format(len(functions)))
		int i = 0;
		int total = functions.size();

		for (var function : functions) {
			i++;
			if (i % 5000 == 0) {
				displayProgress(i, total, "Importing Functions");
			}

			var addr = toAddr((Long) function.get("entry_point"));
			createFunction(addr, "myname"); // TODO: 12/29/2020 no function name
		}

		println("Done.");

	}

	public ArrayList<Long> generateInstructions() {
		println("Generating instructions...");

		ArrayList<Long> addressList = new ArrayList<>();
		try (var fileData = DDInterface.FileData.open(binaryFile)) {
			for (var sec : fileData.sections.iter(DDInterface.Section.class)) {
				if (!sec.executable) {
					continue;
				}

				for (var addr = sec.start; addr < sec.end; addr += batchSize) {
					var textResult = fileData.disassemble(addr, addr + batchSize, false);
					for (var data : textResult.disassembly.iter(DDInterface.Disassembly.class)) {
						var length = data.instruction.length;
						var address = data.address;
						addressList.add(address);
					}
				}

			}
//			println("generated {} instructions successfully!".format(len(address_list)))
		} catch (Exception exception) {
			println("Instructions generation failed!");
		}
		return addressList;
	}

	public void importInstructions(ArrayList<Long> addressList) {
		var instructionSet = new InstructionSet(null);
		var listing = currentProgram.getListing();
		for (var address : addressList) {

			instructionSet.addBlock(new InstructionBlock(toAddr(address)));
		}
		try {
			listing.addInstructions(instructionSet, true);
		} catch (CodeUnitInsertionException e) {
			e.printStackTrace();
		}
	}

	@Override
	protected void run() throws Exception {

		DDInterface.INSTANCE.Initialize(key);
		this.binaryFile = currentProgram.getExecutablePath().substring(1);

		try {
			ArrayList functions = generateFunctions();
			importFunctions(functions);
			ArrayList instructions = generateInstructions();
			importInstructions(instructions);
		} catch (Exception e) {
			print("Something went wrong!");
		}


	}

}