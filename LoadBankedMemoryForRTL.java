
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
      InputStream is = new FileInputStream(
        new File("C:\\Users\\james\\OneDrive\\SwitchFirmware\\SWTG118AS-v2.bin"));
      // Skip the first 0x4000 bytes to get to the first bank
      is.skipNBytes(0x4000);
      long len = 0xc000;
      long blocksAvailable = is.available() % len;

      for (int i = 0; i < blocksAvailable + 1; i++) {
        len = is.available() >= len ? len : is.available();
        if (len > 0) {
        MemoryBlock mb = createMemoryBlock(String.format("BANK%02d", (i+1)), toAddr(0x4000), is, len, true);
        mb.setSourceName("SWTG118AS-v2.bin");
        mb.setExecute(true);
        mb.setRead(true);
        mb.setWrite(false);
        println("Created a memory block: " + mb.getName() + " at " + mb.getStart());  
        }
        
      }
      is.close();
    }
    catch (Exception e) {
      Msg.showInfo(getClass(), null, "Error Creating New Program", e.getMessage());
      println(e.toString());
    }
  }
}
