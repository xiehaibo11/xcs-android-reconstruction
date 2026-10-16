// @category APK.Analysis
// Read-only, reversible Ghidra database experiment; never patches ELF bytes.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import java.io.*;

public class DiagnoseBytealg extends GhidraScript {
  long[] entries = {0x15af40,0x15b400,0x15b420,0x15ae90,0x15b310};
  long[] ends = {0x15af54,0x15b414,0x15b434,0x15af3c,0x15b3f4};
  File out;
  void attempt(String phase,PrintWriter log) throws Exception {
    DecompInterface d=new DecompInterface(); d.openProgram(currentProgram);
    try {
      for(long e:entries) {
        Function f=getFunctionAt(toAddr(e));
        if(f==null){log.println(phase+"\t"+Long.toHexString(e)+"\tabsent");continue;}
        DecompileResults r=d.decompileFunction(f,30,monitor);
        boolean ok=r.decompileCompleted()&&r.getDecompiledFunction()!=null;
        log.println(phase+"\t"+Long.toHexString(e)+"\t"+ok+"\t"+f.getCallingConventionName()+"\t"+f.getSignature()+"\t"+f.getBody()+"\t"+r.getErrorMessage().replace('\n',' '));log.flush();
        if(ok)try(PrintWriter c=new PrintWriter(new File(out,phase+"-"+Long.toHexString(e)+".c"),"UTF-8")){
          c.println("/* Diagnostic Ghidra C after explicit function/flow annotations. Not recovered original source; annotations and warnings must be audited. */");
          c.println(r.getDecompiledFunction().getC());
        }
      }
    } finally {d.dispose();}
  }
  public void run() throws Exception {
    out=new File(getScriptArgs()[0]);out.mkdirs();
    int tx=currentProgram.startTransaction("Temporary bytealg boundary diagnosis");
    try(PrintWriter log=new PrintWriter(new File(out,"status.tsv"),"UTF-8")) {
      log.println("phase\taddress\tcomplete\tcalling_convention\tsignature\tbody\terror");
      attempt("baseline",log);
      for(int i=0;i<3;i++)getFunctionAt(toAddr(entries[i])).setBody(new AddressSet(toAddr(entries[i]),toAddr(ends[i]-1)));
      for(int i=3;i<5;i++)if(getFunctionAt(toAddr(entries[i]))==null)
        currentProgram.getFunctionManager().createFunction("diagnostic_"+Long.toHexString(entries[i]),toAddr(entries[i]),new AddressSet(toAddr(entries[i]),toAddr(ends[i]-1)),SourceType.USER_DEFINED);
      attempt("metadata_boundaries",log);
      for(int i=0;i<3;i++)getInstructionAt(toAddr(ends[i]-4)).setFlowOverride(FlowOverride.CALL_RETURN);
      attempt("explicit_tail_calls",log);
    } finally {currentProgram.endTransaction(tx,false);}
  }
}
