
/*
 * Load all of the Symbols from the AT51 Output
 *
 */
// @category Analysis.8051
import java.io.*;
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.address.Address;

public class LoadAT518051Symbols extends GhidraScript {
  public void run() throws Exception {

    File symbols = askFile("Load symbolfiles", "Do it!");
    try (Scanner scanner = new Scanner(symbols)) {
      while (scanner.hasNextLine()) {
        String line = scanner.nextLine();
        String[] split = line.split(" ");
        Address addr = toAddr(split[0]);
        
        if (addr != null) {
          Function funcAddr = getFunctionAt(addr);
          if (funcAddr == null)
          {
              disassemble(addr);
              funcAddr = createFunction(addr, split[1]);
          }
          funcAddr.setName(split[1], SourceType.IMPORTED);
          // Parse the format of the function name
        }
      }
    }
    catch (Exception e) {
      e.printStackTrace();
    }

    // for (int j = 0; j < howMany; j++) {
    //   createBankFunc(j+2);
    // }
  }
}
