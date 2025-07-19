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

      // Example line: 
      // 0x04ce   [?C?CLDPTR]             char (8-bit) load from general pointer
      while (scanner.hasNextLine()) {
        String line = scanner.nextLine();
        String[] split = line.split("\s+");
        
        // Convert hex string to integer address
        if (split.length < 2 || !split[0].startsWith("0x")) {
          continue; // Skip lines that don't have an address or are malformed
        }

       // Remove the "0x" prefix
        String cleanHex = split[0].substring(2);

        // Convert to int
        int intValue = Integer.parseInt(cleanHex, 16);
        
        int bankNumber = intValue / 0x4000;
        int offset = intValue % 0x4000;
        // Adjust offset for banked memory
        offset = bankNumber > 0 ? offset + 0x4000 : offset; 
        // Format the address as BANKxx:offset
        // If bankNumber is 0, just use the offset in hex format
        String bankAddr = bankNumber > 0 ? String.format("BANK%02d:%s", bankNumber, Integer.toHexString(offset)) : Integer.toHexString(offset);
        println("Found symbol at: " + bankAddr);
        Address addr = toAddr(bankAddr);
        
        if (addr != null) {
          Function funcAddr = getFunctionAt(addr);
          if (funcAddr == null)
          {
              disassemble(addr);
              funcAddr = createFunction(addr, split[1]);
              funcAddr.setCallingConvention("__keilinternal");
          }
          funcAddr.setName(split[1], SourceType.IMPORTED);
          // Parse the format of the function name
        }
      }
    }
    catch (Exception e) {
      e.printStackTrace();
    }
  }
}
