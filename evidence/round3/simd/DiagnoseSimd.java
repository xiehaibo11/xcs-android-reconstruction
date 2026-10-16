// @category APK.Analysis
// Temporary NOP ablations deliberately change semantics for diagnosis only.
// Every experiment is rolled back; exported C is never a reconstructed program.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.util.*;

public class DiagnoseSimd extends GhidraScript {
  long[][] ranges={{0x15ae90,0x15af3c},{0x15b310,0x15b3f4}};
  File out;
  void attempt(String name,long start,PrintWriter log,boolean debug) throws Exception {
    DecompInterface d=new DecompInterface();d.setOptions(new DecompileOptions());d.openProgram(currentProgram);
    try {
      if(debug)d.enableDebug(new File(out,name+".xml"));
      DecompileResults r=d.decompileFunction(getFunctionAt(toAddr(start)),30,monitor);
      boolean ok=r.decompileCompleted()&&r.getDecompiledFunction()!=null;
      log.println(Long.toHexString(start)+"\t"+name+"\t"+ok+"\t"+r.getErrorMessage().replace('\n',' '));log.flush();
      if(ok && (name.contains("all_neon")||name.contains("baseline")||name.contains("equivalent_ldp")))
        try(PrintWriter c=new PrintWriter(new File(out,name+".c"),"UTF-8")){
          c.println(name.contains("equivalent_ldp")
            ? "/* Diagnostic Ghidra C from explicitly documented LD1-to-LDP normalization. Not original source, not the compiled replacement implementation. */"
            : "/* DIAGNOSTIC ABLATION, semantics deliberately changed; NOT a replacement implementation. */");
          c.println(r.getDecompiledFunction().getC());
        }
    }finally{d.dispose();}
  }
  public void run() throws Exception {
    out=new File(getScriptArgs()[0]);out.mkdirs();
    int tx=currentProgram.startTransaction("Temporary SIMD diagnostic");
    try(PrintWriter log=new PrintWriter(new File(out,"status.tsv"),"UTF-8");
        PrintWriter ops=new PrintWriter(new File(out,"instruction_pcode.txt"),"UTF-8")) {
      log.println("function\texperiment\tcompleted\terror");
      for(long a:new long[]{0x15af40,0x15b400,0x15b420}) {
        getFunctionAt(toAddr(a)).setBody(new AddressSet(toAddr(a),toAddr(a+19)));
        getInstructionAt(toAddr(a+16)).setFlowOverride(FlowOverride.CALL_RETURN);
      }
      for(long[] range:ranges) {
        Function f=getFunctionAt(toAddr(range[0]));
        if(f==null)currentProgram.getFunctionManager().createFunction("simd_"+Long.toHexString(range[0]),toAddr(range[0]),new AddressSet(toAddr(range[0]),toAddr(range[1]-1)),SourceType.USER_DEFINED);
        List<Long> neon=new ArrayList<>();
        for(long a=range[0];a<range[1];a+=4) {
          Instruction i=getInstructionAt(toAddr(a));String s=i.toString();
          ops.println(Long.toHexString(a)+" "+s);
          for(var p:i.getPcode())ops.println("  "+p);
          if(s.matches(".*\\b[vdh][0-9]+(?:[.\\[ ,]).*"))neon.add(a);
        }
        ops.flush();
        attempt("baseline_"+Long.toHexString(range[0]),range[0],log,true);
        for(long a:neon) {
          byte[] original=getBytes(toAddr(a),4);
          try {clearListing(toAddr(a),toAddr(a+3));setBytes(toAddr(a),new byte[]{0x1f,0x20,0x03,(byte)0xd5});disassemble(toAddr(a));
            attempt("nop_"+Long.toHexString(a),range[0],log,false);
          }finally{clearListing(toAddr(a),toAddr(a+3));setBytes(toAddr(a),original);disassemble(toAddr(a));}
        }
        Map<Long,byte[]> originals=new LinkedHashMap<>();
        try {
          for(long a:neon){originals.put(a,getBytes(toAddr(a),4));clearListing(toAddr(a),toAddr(a+3));setBytes(toAddr(a),new byte[]{0x1f,0x20,0x03,(byte)0xd5});disassemble(toAddr(a));}
          attempt("all_neon_nop_"+Long.toHexString(range[0]),range[0],log,false);
        }finally{for(var p:originals.entrySet()){long a=p.getKey();clearListing(toAddr(a),toAddr(a+3));setBytes(toAddr(a),p.getValue());disassemble(toAddr(a));}}
        originals.clear();
        try {
          long[] loads=range[0]==0x15ae90 ? new long[]{0x15aeec} : new long[]{0x15b338,0x15b374};
          for(long a:loads) {
            originals.put(a,getBytes(toAddr(a),4));clearListing(toAddr(a),toAddr(a+3));
            setBytes(toAddr(a),new byte[]{(byte)(range[0]==0x15ae90?0x01:0x61),0x08,(byte)0xc1,(byte)0xac});disassemble(toAddr(a));
          }
          attempt("equivalent_ldp_"+Long.toHexString(range[0]),range[0],log,true);
        }finally{for(var p:originals.entrySet()){long a=p.getKey();clearListing(toAddr(a),toAddr(a+3));setBytes(toAddr(a),p.getValue());disassemble(toAddr(a));}}
      }
    }finally{currentProgram.endTransaction(tx,false);}
  }
}
