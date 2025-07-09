
/*
 * Searches all Mov R3, 0x82 to 0xC0 instructions in the program and reads the next two instructions.
 * It extracts the values from R2 and R1 registers and combines them with R3 to form a string address.
 * It then adds a string reference to the instruction address pointing to the string address.
*/
// @category Analysis.8051

import com.debugthings.ghidra.utilities.Utilities;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;

public class FindMovR3AndReadNextInstructions extends GhidraScript {

    Utilities util = new Utilities(this);

    @Override
    protected void run() throws Exception {

        Memory memory = currentProgram.getMemory();
        Address startAddr = memory.getMinAddress();

        // Define MOV R3 opcode pattern
        byte[] movR3Pattern = { (byte) 0x7b }; // MOV R3, imm

        // Define the mask for the MOV R3 opcode
        // The mask indicates which bytes are significant in the pattern
        // Here, we assume the first byte is significant (MOV R3) and the second
        // byte is an immediate value (imm) that can vary, hence we use 0
        // mask for the second byte.
        byte[] movR3PatternMask = { (byte) 0xff }; // MOV R3, imm

        // Search for MOV R3 using findBytes()
        Address matchAddr =
            memory.findBytes(startAddr, movR3Pattern, movR3PatternMask, true, monitor);
        while (matchAddr != null) {
            Instruction instr = getInstructionAt(matchAddr);

            // Check if the instruction is MOV R3, immediate value
            if (instr != null && instr.getMnemonicString().equals("MOV") &&
                instr.getInputObjects().length == 1) {
                util.getValuesFromRegistersR3(instr);
                
            }
            // Continue searching for more occurrences
            matchAddr =
                memory.findBytes(matchAddr.add(2), movR3Pattern, movR3PatternMask, true, monitor);
        }

    }
}
