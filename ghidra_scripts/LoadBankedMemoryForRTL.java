/*
 * Reads the input file and loads all banked code spaces
 *
 */
// @category Analysis.8051
import java.io.*;
import ghidra.util.Msg;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.MemoryBlock;

public class LoadBankedMemoryForRTL extends GhidraScript {
  public void run() throws Exception {

    try {
      File symbols = askFile("Load RTL Firmware", "Do it!");
      InputStream is = new FileInputStream(symbols);
      // Skip the first 0x4000 bytes to get to the first bank
      is.skipNBytes(0x4000);
      // Each bank is 0xc000 bytes long, so we can read in blocks of that size
      long len = 0xc000;

      int bankNumber = 1;
      do {
        // Read the next 0xc000 bytes or until the end of the file
        len = is.available() >= len ? len : is.available();
        if (len > 0) {
          MemoryBlock mb =
            createMemoryBlock(String.format("BANK%02d", bankNumber++), toAddr(0x4000), is, len, true);
          mb.setSourceName(symbols.getName());
          mb.setExecute(true);
          mb.setRead(true);
          mb.setWrite(false);
          println("Created a memory block: " + mb.getName() + " at " + mb.getStart());
        }
      } while (is.available() > 0);
      is.close();
    }
    catch (Exception e) {
      Msg.showInfo(getClass(), null, "Error Creating New Program", e.getMessage());
      println(e.toString());
    }
  }
}
