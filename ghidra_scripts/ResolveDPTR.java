
/*
 * Loops through the MOV DPTR mnemonics and sets the references
*/
// @category Analysis.8051

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;

public class ResolveDPTR extends GhidraScript {
  public void run() throws Exception {
    resolveDPTRREf();
  }

  private void resolveDPTRREf() {

    // Find all instructions that use the DPTR register to load a value
    ReferenceManager referenceManager = currentProgram.getReferenceManager();
    if (referenceManager == null) {
      println("No reference manager found in the current program.");
      return;
    }
    println("Finding all references to DPTR...");
    Listing listing = currentProgram.getListing();
    InstructionIterator iter = listing.getInstructions(true);

    while (iter.hasNext()) {
      Instruction inst = iter.next();
      var dptrAddr = inst.getAddress();

      if (dptrAddr == null) {
        continue; // Skip if the instruction address is null
      }
      String mnemonic = inst.getMnemonicString();
      if (!mnemonic.equals("MOV")) {
        continue; // Only interested in MOV instructions
      }

      Object[] opObjects = inst.getOpObjects(0);
      if (opObjects.length > 0 && opObjects[0] instanceof Register) {
        Register reg = (Register) opObjects[0];
        if (reg.getName().equals("DPTR")) {
          // We found a MOV DPTR instruction, now we can process it
          println("Found MOV DPTR at: " + dptrAddr);

          // Get the address value from the second operand
          Object[] addrOperand = inst.getOpObjects(1);
          if (addrOperand.length > 0 && addrOperand[0] instanceof Scalar) {
            Scalar addrScalar = (Scalar) addrOperand[0];
            long addrValue = addrScalar.getValue();
            println("DPTR value: " + Long.toHexString(addrValue));

            // Create a reference to the address
            Address refAddress = currentProgram.getAddressFactory()
                .getAddressSpace("EXTMEM")
                .getAddress(addrValue);
            Reference refToAdd =
              referenceManager.addMemoryReference(dptrAddr, refAddress, RefType.DATA,
                null, 0);
            referenceManager.setPrimary(refToAdd, true);
            println("Added reference from " + dptrAddr + " to " + refAddress);
          }
        }
      }
    }
  }
}
