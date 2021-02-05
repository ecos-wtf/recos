// Identify calls to debug logging functions, re-construct the debug
// logging parameters and rename the calling function based on that
// string.
//
// Example: a function do: debug_logger(2, "Entering func: BcmEcosSocket::Bind"),
// we can consider the calling function is BcmEcosSocket::Bind.
//
//@author Quentin Kaiser <quentin@ecos.wtf>
//@category Functions

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class DebugLogsAnnotateFunctions extends GhidraScript {

	public HashMap<Long, String> autoMapFunctions3(Function targetFunction) {

		HashMap<Long, String> toRename = new HashMap<Long, String>();
		// String functionName = targetFunction.getName();

		// get the logging function entry point
		Address functionAddress = targetFunction.getEntryPoint();

		// get all xrefs to that logging function by using the entry point as ref point
		ReferenceManager refmanager = currentProgram.getReferenceManager();
		ReferenceIterator referenceIter = refmanager.getReferencesTo(functionAddress);

		// for each xref that has been identified
		while (referenceIter.hasNext()) {
			// if it's a call to the logging function
			Reference ref = referenceIter.next();
			if (!ref.getReferenceType().isCall()) {
				continue;
			}

			// we get the calling function by referencing the call address
			Address src = ref.getFromAddress();
			Function caller = getFunctionContaining(src);
			if (caller == null || caller.isThunk()) {
				continue;
			}

			/**
			 * these logging functions receive the calling function name string as second
			 * parameter, so we need to get the value that is put into register $a1
			 * 
			 * All calls to that function resembles this, with the high bits put into $a1
			 * with lui one instruction before the call, and the low bits put into $a1 with
			 * addiu one instruction after the call.
			 * 
			 * Remember that instruction pipelining and delay slots make the instruction
			 * after the call execute _before_ the call.
			 * 
			 * 80052270 3c 05 80 f2 lui a1,0x80f2 80052274 0c 12 e6 05 jal debug_logger3
			 * 80052278 24 a5 18 44 _addiu a1, a1, 0x1844
			 */

			long arg1Offset = 0;

			/**
			 * We go one instruction below (substract 4) and get the scalar value of the
			 * second operand to 'lui'.
			 */
			Address arg1Load = src.subtract(4);
			Instruction instruction = getInstructionAt(arg1Load);
			Object inputs[] = instruction.getInputObjects();
			if (inputs.length > 1) {
				if (inputs[0].getClass() == ghidra.program.model.lang.Register.class
						&& inputs[1].getClass() == ghidra.program.model.scalar.Scalar.class) {
					Register r = (Register) inputs[0];
					Scalar s = (Scalar) inputs[1];
					if (r.getName().contains("a1") || r.getName().contains("s")) {
						arg1Offset += s.getValue() << 16;
					}
				} else if (inputs[0].getClass() == ghidra.program.model.scalar.Scalar.class
						&& inputs[1].getClass() == ghidra.program.model.scalar.Scalar.class) {
					Scalar s1 = (Scalar) inputs[0];
					Scalar s2 = (Scalar) inputs[1];
					if (s1.getValue() == 0x10) {
						arg1Offset += s2.getValue() << 16;
					}
				}
			}

			/**
			 * We go one instruction below (add 4) and get the scalar value of the second
			 * operand to 'addui'.
			 */
			arg1Load = src.add(4);
			instruction = getInstructionAt(arg1Load);
			inputs = instruction.getInputObjects();
			if (inputs.length > 1) {
				if (inputs[0].getClass() == ghidra.program.model.lang.Register.class
						&& inputs[1].getClass() == ghidra.program.model.scalar.Scalar.class) {
					Register r = (Register) inputs[0];
					Scalar s = (Scalar) inputs[1];
					if (r.getName().contains("a1") || r.getName().contains("s")) {
						arg1Offset += s.getValue();
					}
				} else if (inputs[0].getClass() == ghidra.program.model.scalar.Scalar.class
						&& inputs[1].getClass() == ghidra.program.model.scalar.Scalar.class) {
					Scalar s1 = (Scalar) inputs[0];
					Scalar s2 = (Scalar) inputs[1];
					if (s1.getValue() == 0x16) {
						arg1Offset += s2.getValue();
					}
				} else if (inputs[0].getClass() == ghidra.program.model.scalar.Scalar.class
						&& inputs[1].getClass() == ghidra.program.model.lang.Register.class) {
					Register r = (Register) inputs[1];
					Scalar s = (Scalar) inputs[0];
					if (r.getName().contains("a1") || r.getName().contains("s")) {
						arg1Offset += s.getValue();
					}
				}
			}

			// we adjust our value to 32 bits
			if (arg1Offset > 0x100000000L) {
				arg1Offset = arg1Offset ^ 0x100000000L;
			}

			// we cast it as a FlatAPI Address object
			Address arg1Address = toAddr(arg1Offset);

			try {
				byte[] arg1Value = getBytes(arg1Address, 60);
				String[] s = new String(arg1Value).split("\0");
				if (s.length > 1 && !s[0].isEmpty() && !s[0].contains(" ") && !s[0].contains(".")) {
					toRename.put(caller.getEntryPoint().getOffset(), s[0]);
				}
			} catch (MemoryAccessException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return toRename;
	}

	public HashMap<Long, String> autoMapFunctions5(Function targetFunction) {

		/**
		 * these logging functions receive the calling function name string as second
		 * parameter, so we need to get the value that is put into register $a1
		 * 
		 * All calls to that function resembles this, with the high bits put into $a1
		 * with lui two instructions before the call, and the low bits put into $a1 with
		 * addiu one instruction before the call.
		 * 
		 * 80298928 3c 05 80 fb lui a1, 0x80fb 8029892c 24 a5 3b 30 addiu a1, a1, 0x3b30
		 * 80298930 0c 12 e5 94 jal debug_logger4
		 */

		HashMap<Long, String> toRename = new HashMap<Long, String>();

		// get the logging function entry point
		Address functionAddress = targetFunction.getEntryPoint();

		// get all xrefs to that logging function by using the entry point as ref point
		ReferenceManager refmanager = currentProgram.getReferenceManager();
		ReferenceIterator referenceIter = refmanager.getReferencesTo(functionAddress);

		// for each xref that has been identified
		while (referenceIter.hasNext()) {
			// if it's a call to the logging function
			Reference ref = referenceIter.next();
			if (!ref.getReferenceType().isCall()) {
				continue;
			}

			// we get the calling function by referencing the call address
			Address src = ref.getFromAddress();
			Function caller = getFunctionContaining(src);
			if (caller == null || caller.isThunk()) {
				continue;
			}

			long arg1Offset = 0;

			/**
			 * We go one instruction below (substract 4) and get the scalar value of the
			 * second operand to 'addui'.
			 */
			Address arg1Load = src.subtract(4);
			Instruction instruction = getInstructionAt(arg1Load);
			Object inputs[] = instruction.getInputObjects();

			if (inputs.length > 1) {
				if (inputs[0].getClass() == ghidra.program.model.lang.Register.class
						&& inputs[1].getClass() == ghidra.program.model.scalar.Scalar.class) {
					Register r = (Register) inputs[0];
					Scalar s = (Scalar) inputs[1];
					if (r.getName().contains("a1") || r.getName().contains("s")) {
						arg1Offset += s.getValue() << 16;
					}
				} else if (inputs[0].getClass() == ghidra.program.model.scalar.Scalar.class
						&& inputs[1].getClass() == ghidra.program.model.scalar.Scalar.class) {
					Scalar s1 = (Scalar) inputs[0];
					Scalar s2 = (Scalar) inputs[1];
					if (s1.getValue() == 0x10) {
						arg1Offset += s2.getValue() << 16;
					}
				}
			}

			/**
			 * We go one instruction below (add 4) and get the scalar value of the second
			 * operand to 'lui'.
			 */

			arg1Load = src.add(4);
			instruction = getInstructionAt(arg1Load);
			inputs = instruction.getInputObjects();
			if (inputs.length > 1) {
				if (inputs[0].getClass() == ghidra.program.model.lang.Register.class
						&& inputs[1].getClass() == ghidra.program.model.scalar.Scalar.class) {
					Register r = (Register) inputs[0];
					Scalar s = (Scalar) inputs[1];
					if (r.getName().contains("a1") || r.getName().contains("s")) {
						arg1Offset += s.getValue();
					}
				} else if (inputs[0].getClass() == ghidra.program.model.scalar.Scalar.class
						&& inputs[1].getClass() == ghidra.program.model.scalar.Scalar.class) {
					Scalar s1 = (Scalar) inputs[0];
					Scalar s2 = (Scalar) inputs[1];
					if (s1.getValue() == 0x16) {
						arg1Offset += s2.getValue();
					}
				} else if (inputs[0].getClass() == ghidra.program.model.scalar.Scalar.class
						&& inputs[1].getClass() == ghidra.program.model.lang.Register.class) {
					Register r = (Register) inputs[1];
					Scalar s = (Scalar) inputs[0];
					if (r.getName().contains("a1") || r.getName().contains("s")) {
						arg1Offset += s.getValue();
					}
				}
			}

			if (arg1Offset > 0x100000000L) {
				arg1Offset = arg1Offset ^ 0x100000000L;
			}

			if (arg1Offset < 0xffffffffL) {
				Address arg1Address = toAddr(arg1Offset);
				try {
					byte[] arg1Value = getBytes(arg1Address, 60);
					String[] s = new String(arg1Value).split("\0");
					if (s.length > 1 && !s[0].isEmpty()) {
						Pattern p = Pattern.compile("^([a-zA-Z0-9]+[:][:][a-zA-Z0-9]+)");
						Matcher m = p.matcher(s[0]);

						if (m.find()) {
							toRename.put(caller.getEntryPoint().getOffset(), m.group(0));
						}
					}
				} catch (MemoryAccessException e) {
					e.printStackTrace();
				}
			}
		}
		return toRename;
	}

	public HashMap<Long, String> autoMapFunctions4(Function targetFunction) {

		HashMap<Long, String> toRename = new HashMap<Long, String>();

		// get the logging function entry point
		Address functionAddress = targetFunction.getEntryPoint();

		// get all xrefs to that logging function by using the entry point as ref point
		ReferenceManager refmanager = currentProgram.getReferenceManager();
		ReferenceIterator referenceIter = refmanager.getReferencesTo(functionAddress);

		// for each xref that has been identified
		while (referenceIter.hasNext()) {
			// if it's a call to the logging function
			Reference ref = referenceIter.next();
			if (!ref.getReferenceType().isCall()) {
				continue;
			}

			// we get the calling function by referencing the call address
			Address src = ref.getFromAddress();
			Function caller = getFunctionContaining(src);
			if (caller == null || caller.isThunk()) {
				continue;
			}

			long arg1Offset = 0;

			/**
			 * these logging functions receive the calling function name string as second
			 * parameter, so we need to get the value that is put into register $a1
			 * 
			 * All calls to that function resembles this, with the high bits put into $s1
			 * with lui two instructions before the call, and the low bits put into $a1 with
			 * addiu one instruction before the call.
			 * 
			 * 801a7618 3c 11 80 f7 lui s1,0x80f7 801a761c 26 25 18 d4 addiu a1, s1, 0x18d4
			 * 801a7620 0c 12 e5 94 jal debug_logger4
			 */

			/**
			 * We go two instructions below (substract 8) and get the scalar value of the
			 * second operand to 'lui'.
			 */
			Address arg1Load = src.subtract(8);
			Instruction instruction = getInstructionAt(arg1Load);
			Object inputs[] = instruction.getInputObjects();

			if (inputs.length > 1) {
				if (inputs[0].getClass() == ghidra.program.model.lang.Register.class
						&& inputs[1].getClass() == ghidra.program.model.scalar.Scalar.class) {
					Register r = (Register) inputs[0];
					Scalar s = (Scalar) inputs[1];
					if (r.getName().contains("s1")) {
						arg1Offset += s.getValue() << 16;
					}
				} else if (inputs[0].getClass() == ghidra.program.model.scalar.Scalar.class
						&& inputs[1].getClass() == ghidra.program.model.scalar.Scalar.class) {
					Scalar s1 = (Scalar) inputs[0];
					Scalar s2 = (Scalar) inputs[1];
					if (s1.getValue() == 0x10) {
						arg1Offset += s2.getValue() << 16;
					}
				}
			}

			/**
			 * We go one instruction below (substract 4) and get the scalar value of the
			 * second operand to 'lui'.
			 */
			arg1Load = src.subtract(4);
			instruction = getInstructionAt(arg1Load);
			inputs = instruction.getInputObjects();
			if (inputs.length > 1) {
				if (inputs[0].getClass() == ghidra.program.model.lang.Register.class
						&& inputs[1].getClass() == ghidra.program.model.scalar.Scalar.class) {
					Register r = (Register) inputs[0];
					Scalar s = (Scalar) inputs[1];
					if (r.getName().contains("a1") || r.getName().contains("s")) {
						arg1Offset += s.getValue();
					}
				} else if (inputs[0].getClass() == ghidra.program.model.scalar.Scalar.class
						&& inputs[1].getClass() == ghidra.program.model.scalar.Scalar.class) {
					Scalar s1 = (Scalar) inputs[0];
					Scalar s2 = (Scalar) inputs[1];
					if (s1.getValue() == 0x16) {
						arg1Offset += s2.getValue();
					}
				} else if (inputs[0].getClass() == ghidra.program.model.scalar.Scalar.class
						&& inputs[1].getClass() == ghidra.program.model.lang.Register.class) {
					Register r = (Register) inputs[1];
					Scalar s = (Scalar) inputs[0];
					if (r.getName().contains("a1") || r.getName().contains("s")) {
						arg1Offset += s.getValue();
					}
				}
			}

			if (arg1Offset > 0x100000000L) {
				arg1Offset = arg1Offset ^ 0x100000000L;
			}

			if (arg1Offset < 0xffffffffL) {
				Address arg1Address = toAddr(arg1Offset);
				try {
					byte[] arg1Value = getBytes(arg1Address, 60);
					String[] s = new String(arg1Value).split("\0");
					if (s.length > 1 && !s[0].isEmpty()) {
						Pattern p = Pattern.compile("^([a-zA-Z0-9]+[:][:][a-zA-Z0-9]+)");
						Matcher m = p.matcher(s[0]);
						if (m.find()) {
							toRename.put(caller.getEntryPoint().getOffset(), m.group(0));
						}
					}
				} catch (MemoryAccessException e) {
					e.printStackTrace();
				}
			}
		}
		return toRename;
	}

	/**
	 * We make the assumption that this function name is unique !
	 * 
	 * @param name
	 * @return
	 */
	public final Function getFunctionByName(String name) {
		// we iterate over each symbol, if name match, we return the function
		SymbolTable symbolTable = currentProgram.getSymbolTable();
		SymbolIterator symbolIterator = symbolTable.getSymbolIterator();
		while (symbolIterator.hasNext()) {
			Symbol s = symbolIterator.next();
			if (s.getSymbolType() != SymbolType.FUNCTION || s.isExternal()) {
				continue;
			}
			if (s.getName().equals(name)) {
				return getFunctionAt(s.getAddress());
			}
		}
		return null;
	}

	public int doAutoRename(HashMap<Long, String> toRename) {
		for (Map.Entry<Long, String> me : toRename.entrySet()) {
			printf("[+] Renaming function at 0x%x to %s\n", me.getKey(), me.getValue());
			/**
			 * try { printf("[+] Renaming function at 0x%x to %s\n", me.getKey(),
			 * me.getValue()); getFunctionAt(toAddr(me.getKey())).setName(me.getValue(),
			 * SourceType.USER_DEFINED); } catch (DuplicateNameException |
			 * InvalidInputException e) { // TODO Auto-generated catch block
			 * e.printStackTrace(); }
			 */
		}
		printf("Renamed %d functions\n", toRename.size());
		// printf("xrefs %d functions\n", total);
		return 0;
	}

	public HashMap<Long, String> autoMapFunctions(Function targetFunction) {

		HashMap<Long, String> toRename = new HashMap<Long, String>();

		// get the logging function entry point
		Address functionAddress = targetFunction.getEntryPoint();

		// get all xrefs to that logging function by using the entry point as ref point
		ReferenceManager refmanager = currentProgram.getReferenceManager();
		ReferenceIterator referenceIter = refmanager.getReferencesTo(functionAddress);

		// for each xref that has been identified
		while (referenceIter.hasNext()) {

			// if it's a call to the logging function
			Reference ref = referenceIter.next();
			if (!ref.getReferenceType().isCall()) {
				continue;
			}

			// we get the calling function by referencing the call address
			Address src = ref.getFromAddress();
			Function caller = getFunctionContaining(src);
			if (caller == null || caller.isThunk()) {
				continue;
			}

			/**
			 * these logging functions receive the calling function name string as third
			 * parameter, so we need to get the value that is put into register $a2
			 * 
			 * All calls to that function resembles this, with the high bits put into $a2
			 * with lui one instruction before the call, and the low bits put into $a2 with
			 * addiu one instruction after the call.
			 * 
			 * Remember that instruction pipelining and delay slots make the instruction
			 * after the call execute _before_ the call.
			 * 
			 * 800c13f0 3c 06 80 f3 lui a2, 0x80f3 800c13f4 0c 23 24 68 jal debug_logger
			 * 800c13f8 24 c6 3e a8 addiu a2, a2, 0x3ea8
			 */
			long arg1Offset = 0;

			/**
			 * We go one instruction below (substract 4) and get the scalar value of the
			 * second operand to 'lui'.
			 */
			Address arg1Load = src.subtract(4);
			Instruction instruction = getInstructionAt(arg1Load);
			Object inputs[] = instruction.getInputObjects();
			if (inputs.length > 1) {
				if (inputs[0].getClass() == ghidra.program.model.lang.Register.class
						&& inputs[1].getClass() == ghidra.program.model.scalar.Scalar.class) {
					Register r = (Register) inputs[0];
					Scalar s = (Scalar) inputs[1];
					if (r.getName() == "a3") {
						arg1Offset += s.getValue() << 16;
					}
				} else if (inputs[0].getClass() == ghidra.program.model.scalar.Scalar.class
						&& inputs[1].getClass() == ghidra.program.model.scalar.Scalar.class) {
					Scalar s1 = (Scalar) inputs[0];
					Scalar s2 = (Scalar) inputs[1];
					if (s1.getValue() == 0x10) {
						arg1Offset += s2.getValue() << 16;
					}
				}
			}

			/**
			 * We go one instruction below (add 4) and get the scalar value of the second
			 * operand to 'addui'.
			 */
			arg1Load = src.add(4);
			instruction = getInstructionAt(arg1Load);
			inputs = instruction.getInputObjects();
			if (inputs.length > 1) {
				if (inputs[0].getClass() == ghidra.program.model.lang.Register.class
						&& inputs[1].getClass() == ghidra.program.model.scalar.Scalar.class) {
					Register r = (Register) inputs[0];
					Scalar s = (Scalar) inputs[1];
					if (r.getName().contains("a3")) {
						arg1Offset += s.getValue();
					}
				} else if (inputs[0].getClass() == ghidra.program.model.scalar.Scalar.class
						&& inputs[1].getClass() == ghidra.program.model.scalar.Scalar.class) {
					Scalar s1 = (Scalar) inputs[0];
					Scalar s2 = (Scalar) inputs[1];
					if (s1.getValue() == 0x16) {
						arg1Offset += s2.getValue();
					}
				} else if (inputs[0].getClass() == ghidra.program.model.scalar.Scalar.class
						&& inputs[1].getClass() == ghidra.program.model.lang.Register.class) {
					Register r = (Register) inputs[1];
					Scalar s = (Scalar) inputs[0];
					if (r.getName().contains("a3")) {
						arg1Offset += s.getValue();
					}
				}
			}

			// we adjust our value to 32 bits
			if (arg1Offset > 0x100000000L) {
				arg1Offset = arg1Offset ^ 0x100000000L;
			}

			// we cast it as a FlatAPI Address object
			Address arg1Address = toAddr(arg1Offset + 3);
			//Address arg1Address = toAddr(arg1Offset); ASKEY

			try {
				// we read the string located at the obtained address
				byte[] arg1Value = getBytes(arg1Address, 60);
				String[] s = new String(arg1Value).split("\0");
				//printf("%x %s\n", arg1Address.getOffset(), s[0]);
				// we clean up the address
				if (s.length > 1 && !s[0].contains(" ") && !s[0].contains(".")) {
					// we add the calling function offset and the derived function name
					// to the list of functions to be renamed.
					toRename.put(caller.getEntryPoint().getOffset(), s[0]);
				}
			} catch (MemoryAccessException e) {
				e.printStackTrace();
			}
		}
		return toRename;
	}

	public void run() throws Exception {
		// the logging function names we're interested in
		
		HashMap<Long, String> toRename = new HashMap<Long, String>();
		Function currentFunction;
		String[] functions = {"debug_logger", "debug_logger2"};
		for(String name: functions) {
			currentFunction = getFunctionByName(name);
			if(currentFunction != null) {
				printf("[+] Launching auto-renaming based on xref to %s\n", name);
				toRename.putAll(autoMapFunctions(currentFunction));
			}
			
		}

		currentFunction = getFunctionByName("debug_logger3");
		if(currentFunction != null) {
			toRename.putAll(autoMapFunctions3(currentFunction));
		}

		currentFunction = getFunctionByName("debug_logger4");
		if(currentFunction != null) {
			toRename.putAll(autoMapFunctions4(currentFunction));
		}

		currentFunction = getFunctionByName("debug_logger5");
		if(currentFunction != null) {
			toRename.putAll(autoMapFunctions5(currentFunction));
		}
		
		printf("Renaming %d functions...", toRename.size());
		//doAutoRename(toRename);*/
	}
}
