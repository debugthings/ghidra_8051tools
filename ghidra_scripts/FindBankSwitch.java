/*
 * Loops through the BANK switch statements
  */
// @category Analysis.8051

import ghidra.util.Msg;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.address.GenericAddress;

public class FindBankSwitch extends GhidraScript {
  public void run() throws Exception {

    while (createBankFunc()) {

    }
  }

  private Boolean createBankFunc() {
    Boolean good = false;
    long bankOut = 0;
    try {
      var nextJump = currentAddress;
      if (disassemble(nextJump)) {
        Instruction moveSFR = getInstructionAt(nextJump);
        Instruction bankSwitchMOV = moveSFR.getNext();
        if (bankSwitchMOV.getNumOperands() == 2) {
          GenericAddress sfr = (GenericAddress) bankSwitchMOV.getOpObjects(0)[0];
          if (sfr.getAddressSpace().getName().equals("SFR")) {
            if (bankSwitchMOV.getOpObjects(1)[0] instanceof Scalar) {
              Scalar bank =
                (Scalar) bankSwitchMOV.getOpObjects(1)[0];
              bankOut = bank.getValue();
              Function trampFunc = createFunction(nextJump, "BANK" + bankOut + "TRAMPOLINE");
              if (trampFunc != null) {
                println("Created function " + trampFunc.getName() + " at " + nextJump);
              }

            }
          }
        }
        println("Disassembled instruction at " + nextJump);
      }
      else {
        println("Failed to disassemble instruction at " + nextJump);
      }

    }
    catch (Exception e) {
      Msg.showInfo(getClass(), null, "Error Finding Bank Switch", e.getMessage());
      println(e.toString());
    }
    return good;
  }
}
