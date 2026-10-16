// @category APK.Analysis
// Supplemental decompiler experiment. Output is tool pseudocode, not source.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;

public class RetryNativeGaps extends GhidraScript {
  public void run() throws Exception {
    String[] a = getScriptArgs();
    File output = new File(a[0]); output.mkdirs();
    List<String> addresses = Files.readAllLines(Paths.get(a[1]));
    try (PrintWriter status = new PrintWriter(new File(output, "status.tsv"), "UTF-8")) {
      status.println("address\tstyle\tcompleted\telapsed_ms\terror");
      for (String style : new String[] {"firstpass", "normalize", "decompile"}) {
        DecompInterface d = new DecompInterface();
        d.setSimplificationStyle(style); d.openProgram(currentProgram);
        try {
          for (String entry : addresses) {
            monitor.checkCancelled();
            Function f = currentProgram.getFunctionManager().getFunctionAt(toAddr(entry.trim()));
            if (f == null) {status.println(entry+"\t"+style+"\tfalse\t0\tNo function"); continue;}
            long start = System.nanoTime();
            // Keep diagnostic retries bounded; never execute target native code.
            DecompileResults r = d.decompileFunction(f, style.equals("decompile") ? 90 : 20, monitor);
            boolean ok = r.decompileCompleted() && r.getDecompiledFunction() != null;
            status.println(entry+"\t"+style+"\t"+ok+"\t"+(System.nanoTime()-start)/1000000+"\t"+r.getErrorMessage().replace('\n',' ').replace('\t',' '));
            status.flush();
            if (ok) try(PrintWriter code = new PrintWriter(new File(output, entry+"-"+style+".c"), "UTF-8")) {
              code.println("/* Ghidra "+style+" diagnostic output; NOT original source; NOT assumed compilable or behaviorally complete. */");
              code.println(r.getDecompiledFunction().getC());
            }
          }
        } finally {d.dispose();}
      }
    }
  }
}
