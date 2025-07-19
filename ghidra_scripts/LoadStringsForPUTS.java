
/*
 * Loops through the the various string functions and creates data references for the strings
*/
// @category Analysis.8051
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.CancelledException;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.pcode.VarnodeAST;
import ghidra.program.model.symbol.ReferenceManager;
import com.debugthings.ghidra.utilities.Utilities;;

public class LoadStringsForPUTS extends GhidraScript {

  Utilities util = new Utilities(this);

  public void run() throws Exception {
    createBankFunc();
  }

  private void createBankFunc() throws CancelledException {

    ReferenceManager referenceManager = currentProgram.getReferenceManager();

    // Find symbol by name (modify for the symbol you're looking for)


    List<Symbol> symbols = new ArrayList<Symbol>();

        // Store pointer to XDATA memory
    symbols.addAll(getSymbols("?C?PSTXDATA", currentProgram.getGlobalNamespace()));
    symbols.addAll(getSymbols("?C?PSTXDATA1", currentProgram.getGlobalNamespace()));

    // WRITE_HTTP_STATUS_CODE
    symbols.addAll(getSymbols("WRITE_HTTP_STATUS_CODE", currentProgram.getGlobalNamespace()));
    symbols.addAll(getSymbols("PRINT_AND_LOAD", currentProgram.getGlobalNamespace()));

    // PUTS functions
    symbols.addAll(getSymbols("[_PUTS]", currentProgram.getGlobalNamespace()));
    // symbols.addAll(getSymbols("PUTS_SET21.7", currentProgram.getGlobalNamespace()));
    // symbols.addAll(getSymbols("PUTS_", currentProgram.getGlobalNamespace()));
    // symbols.addAll(getSymbols("PUTS", currentProgram.getGlobalNamespace()));
    // symbols.addAll(getSymbols("PUTS_T", currentProgram.getGlobalNamespace()));
    // symbols.addAll(getSymbols("PUTS_B6", currentProgram.getGlobalNamespace()));
    // symbols.addAll(getSymbols("PUTS_B6_T", currentProgram.getGlobalNamespace()));
    // SPRINTF functions
    symbols.addAll(getSymbols("SPRINTF_CODE", currentProgram.getGlobalNamespace()));
    symbols.addAll(getSymbols("SPRINTF_BANK1", currentProgram.getGlobalNamespace()));
    symbols.addAll(getSymbols("(_SPRINTF)", currentProgram.getGlobalNamespace()));
    // SCANF functions
    symbols.addAll(getSymbols("[SCANF517]", currentProgram.getGlobalNamespace()));
    symbols.addAll(getSymbols("_SCANF517", currentProgram.getGlobalNamespace()));
    symbols.addAll(getSymbols("[_GETS]", currentProgram.getGlobalNamespace()));
    // String manipulation functions
    symbols.addAll(getSymbols("?C?STRCMP", currentProgram.getGlobalNamespace()));
    symbols.addAll(getSymbols("?C?STRCPY", currentProgram.getGlobalNamespace()));
    symbols.addAll(getSymbols("?C?MEMCMP", currentProgram.getGlobalNamespace()));

    if (symbols == null || symbols.isEmpty()) {
      println("Symbols not found, this is not likely if the AT51 symbols were loaded correctly.");
      return;
    }

    HashMap<Function, DecompileResults> symbolMap = new HashMap<>();
    HashMap<DecompileResults, HighFunction> highFunctionMap = new HashMap<>();
    // Decompile the instruction to get the high function
    DecompInterface decompInterface = new DecompInterface();
    decompInterface.openProgram(currentProgram);

    for (Symbol symbol : symbols) {

      monitor.checkCancelled();

      println("Finding references to: " + symbol.getName());

      // Iterate over references to the symbol
      for (var ref : referenceManager.getReferencesTo(symbol.getAddress())) {
        println("Found reference at: " + ref.getFromAddress());
        try {
          Address callToPUTSAddr = ref.getFromAddress();
          Instruction inst = getInstructionAt(callToPUTSAddr);
          Address stringRefAddress = null;
          String mnemonic = inst.getMnemonicString();

          if (mnemonic.equals("LCALL") || mnemonic.equals("ACALL")) {
            println("Found " + mnemonic + " at: " + callToPUTSAddr);

            Function function =
              currentProgram.getFunctionManager().getFunctionContaining(callToPUTSAddr);
            DecompileResults decompileResults = symbolMap.get(function);
            if (decompileResults == null) {
              decompileResults = decompInterface.decompileFunction(function, 0, monitor);
              if (decompileResults == null) {
                println("Decompilation failed for function: " + function.getName() + " at: " +
                  callToPUTSAddr);
                continue;
              }
              symbolMap.put(function, decompileResults);
            }

            HighFunction highFunction = highFunctionMap.get(decompileResults);
            if (highFunction == null) {
              highFunction = decompileResults.getHighFunction();
              if (highFunction == null) {
                println(
                  "High function is null for " + function.getName() + " at: " + callToPUTSAddr);
                continue;
              }
              highFunctionMap.put(decompileResults, highFunction);
            }
            // Find the PcodeOpAST for the LCALL
            PcodeOpAST pcodeOp = null;
            var pcodeOps = highFunction.getPcodeOps(callToPUTSAddr);

            // Iterate through the PcodeOps to find the one that matches the call
            // We are looking for the PcodeOpAST that corresponds to the LCALL or ACALL instruction
            // or branch instructions that lead to the function call
            while (pcodeOps.hasNext()) {
              PcodeOp op = pcodeOps.next();
              if ((op.getOpcode() == PcodeOp.CALL || op.getOpcode() == PcodeOp.BRANCH) &&
                op.getInput(0).getAddress().equals(ref.getToAddress())) {
                pcodeOp = (PcodeOpAST) op;
                break;
              }
            }

            if (pcodeOp == null) {
              println("No PcodeOpAST found for " + mnemonic + " at: " + callToPUTSAddr);
              continue;
            }

            // The PcodeOpAST should have the registers R1, R2, and R3 set; the way the paramter is setup is R1R2R3 are used to pass the address of the string
            // This is a constant value that we'll decode in the switch below
            // Most of these methods can contain multiple inputs so we should attempt to decode them all.
            for (Varnode inputOp : pcodeOp.getInputs()) {
              if (inputOp instanceof VarnodeAST) {
                VarnodeAST varNode = (VarnodeAST) inputOp; // Assuming R1 is the first input
                if (varNode.isConstant() && varNode.getSize() == 3) {
                  // The varnode is a constant, we can extract the value
                  stringRefAddress = util.getRefAddress(varNode.getOffset());
                  util.addStringReference(callToPUTSAddr, stringRefAddress, true);
                }
                else {
                  // If varNode is not constant it is a variable and we need to find all instances of the variable
                  println("Varnode it is variable: " + varNode);
                  continue;
                  // We can try to find the variable in the high function
                }
              }
            }
          }
          else if (mnemonic.equals("JMP") || mnemonic.equals("AJMP") || mnemonic.equals("LJMP") ||
            mnemonic.equals("SJMP")) {

            println("Found " + mnemonic + " at: " + callToPUTSAddr);
            if (!util.getValuesFromRegistersR3(inst)) {
              {
                util.getValuesFromRegistersR5(inst);
              }
            }
          }
        }
        catch (Exception e) {
          println("Error processing reference: " + e.getMessage());
        }
      }
    }
  }
}
