// @category APK.Analysis
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import java.io.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class DeepRustAnalysis extends GhidraScript {
    private LinkedHashMap<Function,LinkedHashSet<String>> roots = new LinkedHashMap<>();
    private void mark(Function f, String reason) {
        if (f != null && !f.isExternal() && !f.isThunk()) roots.computeIfAbsent(f,k->new LinkedHashSet<>()).add(reason);
    }
    public void run() throws Exception {
        String[] args = getScriptArgs();
        File dir = new File(args[0]); dir.mkdirs();
        String[][] entries = {{"001b0180","create_event_stream_wrapper"},{"001b0054","init_app_wrapper"},
          {"001b0504","init_ws_wrapper"},{"001aff28","is_content_ws_wrapper"},{"001b03d8","ws_login_wrapper"},
          {"001b02ac","ws_logout_wrapper"},{"001c64b0","frb_primary_dispatcher"}};
        if (args.length>2) {
            for (String line : Files.readAllLines(Paths.get(args[2]),StandardCharsets.UTF_8)) {
                String[] cols=line.split("\t",2);
                mark(getFunctionAt(toAddr(cols[0].replace("0x",""))),cols[1]);
            }
        } else for (String[] entry : entries) mark(getFunctionAt(toAddr(entry[0])),entry[1]);
        try (PrintWriter xrefs = writer(new File(dir,"string_xrefs.tsv"))) {
            xrefs.println("string_address\tlabel\tref_address\tref_type\tfunction_address\tfunction_name\tdepth");
            for (String line : Files.readAllLines(Paths.get(args[1]),StandardCharsets.UTF_8)) {
                String[] cols = line.split("\t",2);
                Address a = toAddr(cols[0].replace("0x",""));
                Set<Address> visited = new HashSet<>();
                collectRefs(a,a,cols[1],0,visited,xrefs);
            }
        }
        LinkedHashMap<Function,LinkedHashSet<String>> chosen = new LinkedHashMap<>();
        chosen.putAll(roots);
        try (PrintWriter edges = writer(new File(dir,"call_edges.tsv"))) {
            edges.println("caller_address\tcaller_name\tcallee_address\tcallee_name\treason");
            for (Map.Entry<Function,LinkedHashSet<String>> entry : roots.entrySet()) {
                Function f = entry.getKey();
                List<Function> callees = new ArrayList<>(f.getCalledFunctions(monitor));
                callees.sort(Comparator.comparing(c->c.getEntryPoint()));
                for (Function c : callees) {
                    edges.println(f.getEntryPoint()+"\t"+f.getName()+"\t"+c.getEntryPoint()+"\t"+c.getName()+"\t"+String.join(";",entry.getValue()));
                    if (!c.isExternal() && !c.isThunk() && chosen.size()<160) chosen.computeIfAbsent(c,k->new LinkedHashSet<>()).add("callee_of:"+f.getEntryPoint());
                }
            }
        }
        DecompInterface d = new DecompInterface(); d.openProgram(currentProgram);
        try (PrintWriter all = writer(new File(dir,"network_and_bridge.c")); PrintWriter status = writer(new File(dir,"decompile_status.tsv"))) {
            all.println("/* Static Ghidra pseudocode. Approximate recovered types; no live execution. */");
            status.println("address\tname\tcompleted\treasons\terror");
            File funcs = new File(dir,"functions"); funcs.mkdirs();
            for (Map.Entry<Function,LinkedHashSet<String>> entry : chosen.entrySet()) {
                monitor.checkCancelled();
                Function f=entry.getKey(); String reasons=String.join(";",entry.getValue());
                DecompileResults r=d.decompileFunction(f,30,monitor);
                status.println(f.getEntryPoint()+"\t"+f.getName()+"\t"+r.decompileCompleted()+"\t"+reasons+"\t"+r.getErrorMessage().replace('\n',' '));
                String header="\n/* "+f.getName()+" @ "+f.getEntryPoint()+"; "+reasons+" */\n";
                String code=r.decompileCompleted()&&r.getDecompiledFunction()!=null?r.getDecompiledFunction().getC():"/* Decompilation incomplete. */\n";
                all.println(header+code);
                try (PrintWriter w=writer(new File(funcs,f.getEntryPoint()+".c"))) {w.print(header+code);}
            }
        } finally { d.dispose(); }
        println("Deep Rust export roots="+roots.size()+", total="+chosen.size()+", output="+dir);
    }
    private void collectRefs(Address origin,Address dest,String label,int depth,Set<Address> visited,PrintWriter w) throws Exception {
        if (depth>3 || !visited.add(dest)) return;
        ReferenceIterator it=currentProgram.getReferenceManager().getReferencesTo(dest);
        while(it.hasNext()) {
            Reference ref=it.next(); Address from=ref.getFromAddress();
            Function f=getFunctionContaining(from);
            w.println(origin+"\t"+label+"\t"+from+"\t"+ref.getReferenceType()+"\t"+(f==null?"":f.getEntryPoint())+"\t"+(f==null?"":f.getName())+"\t"+depth);
            if(f!=null) mark(f,"string:"+label+"@"+origin);
            else collectRefs(origin,from,label,depth+1,visited,w);
        }
    }
    private PrintWriter writer(File f) throws IOException { return new PrintWriter(new OutputStreamWriter(new FileOutputStream(f),StandardCharsets.UTF_8)); }
}
