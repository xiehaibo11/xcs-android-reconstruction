// Exports function inventory and selected native entry points with direct callees.
// @category APK.Analysis
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class ExportNativeAnalysis extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        File dir = new File(args[0], currentProgram.getName());
        dir.mkdirs();
        LinkedHashSet<Function> roots = new LinkedHashSet<>();
        try (PrintWriter w = writer(new File(dir, "functions.tsv"))) {
            w.println("address\tname\tbytes\texternal\tthunk");
            FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
            while (it.hasNext()) {
                Function f = it.next();
                w.println(f.getEntryPoint()+"\t"+f.getName()+"\t"+f.getBody().getNumAddresses()+"\t"+f.isExternal()+"\t"+f.isThunk());
                if (f.getName().matches(".*(RSABridgeCall|frb_pde_ffi_dispatcher.*|frb_get_rust_content_hash|init_frb_dart_api_dl).*$")) roots.add(f);
            }
        }
        LinkedHashSet<Function> chosen = new LinkedHashSet<>(roots);
        for (Function root : roots) {
            ArrayList<Function> callees = new ArrayList<>(root.getCalledFunctions(monitor));
            callees.sort(Comparator.comparing(f -> f.getEntryPoint()));
            for (Function f : callees) if (!f.isExternal() && !f.isThunk() && chosen.size() < 30) chosen.add(f);
        }
        DecompInterface d = new DecompInterface();
        d.openProgram(currentProgram);
        try (PrintWriter w = writer(new File(dir, "entry_points.c"));
             PrintWriter index = writer(new File(dir, "decompile_status.tsv"))) {
            w.println("/* Ghidra-generated pseudocode; types and names may be approximate. */");
            index.println("address\tname\tcompleted\terror");
            for (Function f : chosen) {
                monitor.checkCancelled();
                DecompileResults r = d.decompileFunction(f, 30, monitor);
                index.println(f.getEntryPoint()+"\t"+f.getName()+"\t"+r.decompileCompleted()+"\t"+r.getErrorMessage().replace('\n',' '));
                w.println("\n/* "+f.getName()+" @ "+f.getEntryPoint()+" */");
                if (r.decompileCompleted() && r.getDecompiledFunction()!=null) w.println(r.getDecompiledFunction().getC());
                else w.println("/* Decompilation incomplete. */");
            }
        } finally { d.dispose(); }
        println("Exported " + chosen.size() + " functions to " + dir);
    }
    private PrintWriter writer(File file) throws IOException {
        return new PrintWriter(new OutputStreamWriter(new FileOutputStream(file), StandardCharsets.UTF_8));
    }
}
