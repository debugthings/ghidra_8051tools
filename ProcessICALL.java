/*
 * Loops through the ICALL statements and sets the THUNK to the function it points to.
*/
// @category Analysis.8051
import ghidra.util.Msg;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.lang.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.GenericAddress;

public class ProcessICALL extends GhidraScript {
  public void run() throws Exception {

    createBankFunc();
    // for (int j = 0; j < howMany; j++) {
    //   createBankFunc(j+2);
    // }
  }

  private void createBankFunc() {

    try {
      var nextJump = currentAddress;
      long addrScalar = 0x0;

      // Let's disassemble the MOV
      if (disassemble(nextJump)) {
        println("Disassembled instruction at " + nextJump);
      }

      Instruction moveOperation = getInstructionAt(nextJump);
      if (moveOperation.getMnemonicString().equals("MOV") &&
        moveOperation.getNumOperands() == 2) {
        Object[] dptrOperandForMov = moveOperation.getOpObjects(0);
        if (dptrOperandForMov.length > 0 && dptrOperandForMov[0] instanceof Register) {
          Register reg = (Register) dptrOperandForMov[0];
          if (reg.getName().equals("DPTR")) {

            Object[] addrOperand = moveOperation.getOpObjects(1);
            if (addrOperand.length > 0) {
              Scalar addr = (Scalar) addrOperand[0];
              addrScalar = addr.getValue();
            }
          }
        }

        Scalar bank = null;
        Function thunkFunction = null;
        // Let's disassemble the LJMP
        // We do this to get the bank and then disassemble the function further down.
        Instruction ljmpInstruction = moveOperation.getNext();
        if (ljmpInstruction.getMnemonicString().equals("LJMP")) {
          // Get the address of the bank method
          Object[] dptrOperand = ljmpInstruction.getOpObjects(0);
          if (dptrOperand.length > 0) {
            if (dptrOperand[0] instanceof GenericAddress) {
              GenericAddress dptrCode = (GenericAddress) dptrOperand[0];

              // Get the bank address from the trampoline method.
              Instruction bankAddr = getInstructionAt(dptrCode).getNext();
              if (bankAddr.getNumOperands() == 2) {
                GenericAddress sfr = (GenericAddress) bankAddr.getOpObjects(0)[0];
                if (sfr.getAddressSpace().getName().equals("SFR")) {
                  if (bankAddr.getOpObjects(1)[0] instanceof Scalar) {
                    bank =
                      (Scalar) bankAddr.getOpObjects(1)[0];
                    String bankOut = String.format("BANK%02d", bank.getValue());
                    // Get the address to pass to the icall function
                    Address icallFunction =
                      getAddressFactory().getAddressSpace(bankOut).getAddress(addrScalar);
                    if (disassemble(icallFunction)) {
                      println("Disassembled function at " + icallFunction);
                    }
                    thunkFunction = createFunction(icallFunction,
                      String.format("BANK%02d_%d", bank.getValue(), addrScalar));
                  }
                }
              }
            }
          }
        }
        Function icallFunc = createFunction(moveOperation.getMinAddress(),
          String.format("ICALL_BANK%02d_%d", bank.getValue(), addrScalar));
        if (thunkFunction != null) {
          icallFunc.setThunkedFunction(thunkFunction);
        }

        currentAddress = ljmpInstruction.getMaxAddress().add(1);

      }
      else {
        println("Failed to disassemble instruction at " + nextJump);
      }

    }
    catch (Exception e) {
      Msg.showInfo(getClass(), null, "Error Finding Bank Switch", e.getMessage());
      println(e.toString());
    }
  }
}
