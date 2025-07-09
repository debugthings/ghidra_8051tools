
import ghidra.program.model.symbol.Symbol;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.VarnodeAST;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;

public class DecodeCFunctions extends GhidraScript {
  public void run() throws Exception {
    createBankFunc();
  }

  private void createBankFunc() {

    ReferenceManager referenceManager = currentProgram.getReferenceManager();

    // Find symbol by name (modify for the symbol you're looking for)
    String symbolName = "PUTS";
    
    // Given this webpage we can determine the encoding of the string:
    // https://www.keil.com/support/docs/1964.htm
    // The string is encoded in the following way:
    // - The first one or two characters are the data type
    // - The next two ro three characters is the function
    // - The remaining characters are the memory location

    /*
     * Algorithm to decode the ?C? helper functions as described in
     * https://www.keil.com/support/docs/1964.htm
     *
     * 1. Iterate through all symbols in the symbol table.
     * 2. For each symbol, check if its name matches the ?C? helper function pattern.
     *    - The pattern is typically: ?C?XXX..., where XXX is the function mnemonic.
     * 3. Parse the symbol name:
     *    - The first 1-2 characters: Data type (e.g., C, I, L, F, D, etc.)
     *    - The next 2-3 characters: Function (e.g., LDI, MOV, ADD, etc.)
     *    - The remaining characters: Memory type/location (e.g., PTR, OPTR, DPTR, etc.)
     * 4. Use the data type to determine register usage for input/output:
     *    - For example, 'C' (char) uses R7:R6 for input/output, 'I' (int) uses R7:R6, etc.
     *    - See the Keil documentation for the full mapping.
     * 5. For LDI functions, handle the increment amount passed in A/B registers.
     * 6. For memory type fields (except PTR and OPTR), decode the memory location.
     * 7. Store or print the decoded information for each helper function.
     */

    // Example: Iterate through all symbols and print those matching the ?C? helper function pattern
    currentProgram.getSymbolTable().getAllSymbols(true);
    for (Symbol symbol : currentProgram.getSymbolTable().getAllSymbols(true)) {
      String name = symbol.getName();
      if (name.startsWith("?C?")) {
        println("Found helper function: " + name);

        // Example decode: ?C?C2I
        // Data type: C
        // Function: 2I (could be MOV, ADD, etc. depending on length)
        // Memory type: (rest of string)

        // Extract data type (first char after ?C?)
        char dataType = name.charAt(3);

        // Extract function mnemonic (next 2-3 chars)
        String functionMnemonic = name.substring(4, Math.min(7, name.length()));

        // Extract memory type/location (rest)
        String memType = name.length() > 7 ? name.substring(7) : "";

        println("  Data Type: " + dataType);
        println("  Function: " + functionMnemonic);
        println("  Memory Type: " + memType);

        // TODO: Use dataType, functionMnemonic, memType to determine register usage and parameters
        // See Keil doc for mapping, e.g.:
        // - 'C' (char): R7:R6
        // - 'I' (int): R7:R6
        // - 'L' (long): R7:R6:R5:R4
        // - 'F' (float): R7:R6:R5:R4
        // - 'D' (double): R7:R6:R5:R4:R3:R2:R1:R0

        // Special handling for LDI function
        if (functionMnemonic.startsWith("LDI")) {
          println("  LDI function: increment amount in A/B registers");
        }

        // Additional decoding logic as needed...
      }
    }

    List<Symbol> symbols = getSymbols(symbolName, currentProgram.getGlobalNamespace());

    if (symbols == null || symbols.isEmpty()) {
      println("Symbol not found: " + symbolName);
      return;
    }

    for (Symbol symbol : symbols) {
      println("Finding references to: " + symbol.getName());

      // Iterate over references to the symbol
      for (var ref : referenceManager.getReferencesTo(symbol.getAddress())) {

        try {
          Address callToPUTSAddr = ref.getFromAddress();
          Instruction inst = getInstructionAt(callToPUTSAddr);

          // Check if this is a LCALL to the PUTS function
          if (inst == null || !inst.getMnemonicString().equals("LCALL")) {
            continue;
          }

          // Decompile the instruction to get the high function
          DecompInterface decompInterface = new DecompInterface();
          decompInterface.openProgram(currentProgram);

          DecompileResults decompileResults = decompInterface.decompileFunction(
            currentProgram.getFunctionManager().getFunctionContaining(callToPUTSAddr), 0,
            null);

          HighFunction highFunction = decompileResults.getHighFunction();
          if (highFunction == null) {
            println("Failed to decompile function at: " + callToPUTSAddr);
            continue;
          }
          // Find the PcodeOpAST for the LCALL
          PcodeOpAST pcodeOp = null;
          var pcodeOps = highFunction.getPcodeOps(callToPUTSAddr);
          ;
          while (pcodeOps.hasNext()) {
            PcodeOp op = pcodeOps.next();
            if (op.getOpcode() == PcodeOp.CALL &&
              op.getInput(0).getAddress().equals(ref.getToAddress())) {
              pcodeOp = (PcodeOpAST) op;
              break;
            }
          }

          if (pcodeOp == null) {
            println("No PcodeOpAST found for LCALL at: " + callToPUTSAddr);
            continue;
          }

          // The PcodeOpAST should have the registers R1, R2, and R3 set; the way the paramter is setup is R1R2R3 are used to pass the address of the string
          // This is a constant value that we'll decode in the switch below
          VarnodeAST varNode = (VarnodeAST) pcodeOp.getInput(1); // Assuming R1 is the first input
          long r1Value = 0x0;

          if (varNode.isConstant()) {
            // If R1 is a constant, we can directly use its value
            r1Value = varNode.getOffset();
          }
          else {
           // If varNode is not constant it is a variable and we need to find all instances of the variable

            println("R1 is not a constant, it is a variable: " + varNode);
            continue;
            // We can try to find the variable in the high function
          }
          

          int addrH = (int) (r1Value >> 16) & 0xFF; // Extract the memory type from R1
          int addrL = (int) (r1Value >> 8) & 0xFF; // Extract the high byte of the address from R1
          int memType = (int) (r1Value & 0xFF); // Extract the low byte of the address from R1

          Address refAddress = null;
          if (memType == 0x00) {
            // Load from the data memory space
            println("Found a PUTS call with R1 value: " + Long.toHexString(r1Value));
          }
          else if (memType == 0x01) {
            // Load from the xdata memory space
            println("Found a PUTS call with R1 value: " + Long.toHexString(r1Value));
          }
          else if (memType == 0xfe) {
            // Load data from the pdata space
            println("Found a PUTS call with unknown R1 value: " + Long.toHexString(r1Value));
          }
          else if (memType == 0xff) {
            // Load from the code memory space
            int bank = 1;
            refAddress = currentProgram.getAddressFactory()
                .getAddressSpace("BANK" + String.format("%02d", bank))
                .getAddress((addrL << 8) | addrH);
          }
          else if (memType < 0xfd) {
            // Load from the banked memory space
            int bank = (memType - 1) & 0x3F; // Adjust for the bank offset
            refAddress = currentProgram.getAddressFactory()
                .getAddressSpace("BANK" + String.format("%02d", bank))
                .getAddress((addrL << 8) | addrH);
          }

          

          // This address is the location of the string in the memory space and we can now create the data type for it
          if (refAddress == null) {
            println(
              "Could not determine reference address for R1 value: " + Long.toHexString(r1Value));
            continue;
          }

          Data d = currentProgram.getListing().getDefinedDataAt(refAddress);
          if (d == null) {
            d = currentProgram.getListing().createData(refAddress, new StringDataType());;
          }
          Reference stringRef = referenceManager.addMemoryReference(callToPUTSAddr, refAddress, RefType.READ, null, 0);
          referenceManager.setPrimary(stringRef, true);
          if (d.getDataType() instanceof StringDataType) {
            println("Created data at " + refAddress + " for PUTS call at " + callToPUTSAddr);
          }
          else {
            println("Data at " + refAddress + " is not a StringDataType, it is: " + d.getDataType());
          }
          
          println("Created data at " + refAddress + " for PUTS call at " + callToPUTSAddr);
          
        }
        catch (Exception e) {
          println("Error processing reference: " + e.getMessage());
        }
      }
    }
  }
}
