import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.listing.Program;
import ghidra.app.script.GhidraScript;

public class EmulateChecksumValidation extends GhidraScript {

    @Override
    public void run() throws Exception {

        MemoryBlock block = currentProgram.getMemory().getBlock("BANK03");
        if (block == null) {
            printerr("Block not found.");
            return;
        }

        Register ctxReg = currentProgram.getLanguage().getContextBaseRegister();
        if (ctxReg == null || !ctxReg.getName().equals("CODE_BANK")) {
            printerr("No CODE_BANK context found.");
            return;
        }

        block.setContextRegisterValue(ctxReg, 3);  // Apply bank-3
        println("Context CODE_BANK=3 applied to code_bank3");
        EmulatorHelper emu = new EmulatorHelper(getCurrentProgram());

        Address loadMagicEntry = getSymbols("LOAD_MAGIC_VALS", null).getFirst().getAddress();
        emu.writeRegister("PC", loadMagicEntry.getOffset()); // Set PC to LOAD_MAGIC_VALS entry point
        emu.setBreakpoint(loadMagicEntry.add(0x49));
        emu.run(monitor);  // Adjust instruction count based on complexity
        println("📍 Emulation started at LOAD_MAGIC_VALS");
        byte[] bytes = emu.readMemory(toAddr("EXTMEM:0x165e"), 0x14);


        // // Entry address for VALIDATE_MAGICNUMBER
        // Address startAddr = getSymbols("VALIDATE_MAGICNUMBER", null).getFirst().getAddress(); // or toAddr(0x...)
        // emu.writeMemory(toAddr(0xe00), new byte[] { 0 }); // Init checksum

        // // Set up other required memory values (e.g., pointer at 0xe0a, counters)
        // emu.writeMemory(toAddr(0xe0a), new byte[] { /* pointer to BANK03:0x5008 */ });
        // emu.writeMemory(toAddr(0xe08), new byte[] { 0 });
        // emu.writeMemory(toAddr(0xe09), new byte[] { 0 });

        // println("📍 Starting emulation at VALIDATE_MAGICNUMBER");

        // // boolean success = emu.run(startAddr, 1000); // Step through max 1000 instructions

        // if (!success) {
        //     println("❌ Emulation failed or halted prematurely.");
        // } else {
        //     byte finalChk = emu.readMemoryByte(toAddr(0xe00));
        //     println("✅ Final checksum value: 0x" + String.format("%02X", finalChk));
        // }

        emu.dispose();
    }
}
