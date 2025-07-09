// @category Analysis.8051
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;

public class EmulateICASEExecution extends GhidraScript {
    @Override
    protected void run() throws Exception {
        // Locate function entry for ICASE
        Function icaseFunction = getFunctionContaining(currentAddress);
        if (icaseFunction == null) {
            println("ICASE function not found.");
            return;
        }
        
        Address startAddr = icaseFunction.getEntryPoint();
        EmulatorHelper emulator = new EmulatorHelper(currentProgram);
        
        emulator.writeRegister(emulator.getPCRegister(), startAddr.getOffsetAsBigInteger());
        emulator.writeStackValue(0,1, 0x67);  // Set stack value (adjust as needed)
        emulator.writeStackValue(-1,1, 0xf2);  // Set stack value (adjust as needed)
        emulator.setBreakpoint(startAddr);  // Set breakpoint at function entry
        emulator.writeRegister("DPTR", 0x67f2);  // Set test value (adjust as needed)
        emulator.writeRegister("R4R5R6R7", 0x1);  // Set test value (adjust as needed)
        println("Starting emulation at: " + startAddr);
        
        long counter = 0;
        // Step through execution until the jump is resolved
        while (!emulator.getPCRegister().getAddress().equals(startAddr.add(10))) {  // Adjust step limit
            emulator.step(monitor);  // Execute one instruction
            Register currentPC = emulator.getPCRegister();
            ;
            println("Executing at: " + toHexString(emulator.readRegister(currentPC).longValue(), false, true) + ", DPTR = " + toHexString(emulator.readRegister("DPTR").longValue(), false, true) + ", ACC = " + toHexString(emulator.readRegister("ACC").longValue(), false, true));
            counter++;
            if (counter > 18) {  // Prevent infinite loop
                println("Execution limit reached, stopping emulation.");
                break;
            }
        }

        emulator.dispose();
    }
}
