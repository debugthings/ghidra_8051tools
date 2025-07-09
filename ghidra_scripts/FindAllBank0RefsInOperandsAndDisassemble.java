
/*
 * Searches all Mov R3, 0x82 to 0xC0 instructions in the program and reads the next two instructions.
 * It extracts the values from R2 and R1 registers and combines them with R3 to form a string address.
 * It then adds a string reference to the instruction address pointing to the string address.
*/
// @category Analysis.8051

import com.debugthings.ghidra.utilities.Utilities;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;

public class FindAllBank0RefsInOperandsAndDisassemble extends GhidraScript {

    Utilities util = new Utilities(this);

    @Override
    protected void run() throws Exception {

       Listing listing = currentProgram.getListing();
        
        println("Scanning all instructions for BANK0_Rx operands…");
        int count = 0;

        // Iterate through every instruction in the program
        for (Instruction instr : listing.getInstructions(true)) {
            monitor.checkCancelled();
            Address addr = instr.getAddress();

            // For each operand slot of the instruction
            for (int opIndex = 0; opIndex < instr.getNumOperands(); opIndex++) {
                Object[] opObjs = instr.getOpObjects(opIndex);
                if (opObjs == null) {
                    continue;
                }

                // Check each object in that operand
                for (Object obj : opObjs) {
                    if (obj instanceof Register) {
                        Register reg = (Register) obj;
                        String name = reg.getName();
                        if (name.startsWith("BANK0_R")) {
                            println(addr + "   " +
                                    instr + 
                                    "   operand#" + opIndex + 
                                    " → " + name);
                            count++;
                        }
                    }
                }
            }
            clearListing(addr); // Clear the listing at this address to avoid clutter
            disassemble(addr); // Disassemble the instruction at this address
        }

        println("Found " + count + " BANK0_Rx references.");

    }
}
