// SPDX-License-Identifier: Apache-2.0
// Analyzer automation only; no target code is executed or copied into the runtime.
// @category Research
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

public class StaticEvidence extends GhidraScript {
    private final List<long[]> ranges = new ArrayList<>();
    private String clean(Object value) {
        return String.valueOf(value).replace('\t', ' ').replace('\r', ' ').replace('\n', ' ');
    }
    private String raw(Address a) {
        if (a == null || !a.isMemoryAddress()) return "-";
        long va = a.getOffset();
        for (long[] r : ranges) if (va >= r[0] && va - r[0] < r[1])
            return String.format("0x%x", r[2] + va - r[0]);
        return "-";
    }
    private String owner(Address a) {
        Function f = currentProgram.getFunctionManager().getFunctionContaining(a);
        return f == null ? "-" : f.getEntryPoint().toString();
    }
    private String symbol(Address a) {
        Symbol s = currentProgram.getSymbolTable().getPrimarySymbol(a);
        return s == null ? "-" : clean(s.getName(true));
    }
    private PrintWriter writer(Path out, String name) throws IOException {
        return new PrintWriter(Files.newBufferedWriter(out.resolve(name), StandardCharsets.UTF_8));
    }
    public void run() throws Exception {
        String[] args = getScriptArgs();
        Path out = Paths.get(args[0]);
        for (String line : Files.readAllLines(out.resolve("mapping.tsv"))) {
            if (line.startsWith("va")) continue;
            String[] p = line.split("\t");
            ranges.add(new long[] {Long.decode(p[0]), Long.decode(p[1]), Long.decode(p[2])});
        }
        Set<String> requested = new HashSet<>();
        for (int i = 1; i < args.length; i++) requested.add(args[i].replace("0x", "").toLowerCase());
        FunctionManager fm = currentProgram.getFunctionManager();
        for (String value : requested) {
            Address address = toAddr(Long.parseLong(value, 16));
            if (fm.getFunctionAt(address) == null && fm.getFunctionContaining(address) == null) {
                disassemble(address);
                createFunction(address, "research_" + address);
            }
        }
        Set<Function> chosen = new LinkedHashSet<>();
        try (PrintWriter w = writer(out, "functions.tsv")) {
            w.println("va\traw\tname\tbody_bytes\tthunk");
            for (Function f : fm.getFunctions(true)) {
                w.printf("%s\t%s\t%s\t%d\t%b%n", f.getEntryPoint(), raw(f.getEntryPoint()),
                    clean(f.getName()), f.getBody().getNumAddresses(), f.isThunk());
                String va = f.getEntryPoint().toString().toLowerCase();
                if (requested.contains(va) || requested.contains(va.replaceFirst("^0+", ""))) chosen.add(f);
            }
        }
        String api = "(?i).*(CreateProcess|WaitForDebugEvent|ContinueDebugEvent|ReadProcessMemory|WriteProcessMemory|GetThreadContext|DialogBoxParam|CreateDialogParam|GetOpenFileName|WriteFile|MapViewOfFile|CreateFileMapping).*";
        try (PrintWriter ins = writer(out, "instructions.tsv"); PrintWriter refs = writer(out, "references.tsv")) {
            ins.println("va\traw\tfunction\tbytes\tinstruction");
            refs.println("from_va\traw\tfunction\ttype\tto_va\tsymbol\tto_function");
            for (Instruction i : currentProgram.getListing().getInstructions(true)) {
                monitor.checkCancelled();
                StringBuilder b = new StringBuilder();
                for (byte v : i.getBytes()) b.append(String.format("%02x", v & 255));
                ins.printf("%s\t%s\t%s\t%s\t%s%n", i.getAddress(), raw(i.getAddress()), owner(i.getAddress()), b, clean(i));
            }
            var it = currentProgram.getReferenceManager().getReferenceSourceIterator(currentProgram.getMemory(), true);
            while (it.hasNext()) {
                Address from = it.next();
                for (Reference r : currentProgram.getReferenceManager().getReferencesFrom(from)) {
                    Address to = r.getToAddress();
                    String name = symbol(to);
                    refs.printf("%s\t%s\t%s\t%s\t%s\t%s\t%s%n", from, raw(from), owner(from), r.getReferenceType(), to, name, owner(to));
                    Function f = fm.getFunctionContaining(from);
                    if (f != null && !f.isThunk() && name.matches(api) && chosen.size() < 64) chosen.add(f);
                }
            }
        }
        if (fm.getFunctionCount() < 180) {
            for (Function f : fm.getFunctions(true)) if (!f.isThunk()) chosen.add(f);
        }
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        try (PrintWriter w = writer(out, "decompilation.txt")) {
            w.println("PRIVATE RESEARCH OUTPUT. License of target unknown. Not runtime source.");
            for (Function f : chosen) {
                monitor.checkCancelled();
                w.printf("\n=== %s %s raw=%s ===%n", f.getEntryPoint(), f.getName(), raw(f.getEntryPoint()));
                DecompileResults r = decomp.decompileFunction(f, 45, monitor);
                if (r.decompileCompleted()) w.println(r.getDecompiledFunction().getC());
                else w.println("DECOMPILE_FAILED " + r.getErrorMessage());
            }
        } finally { decomp.dispose(); }
        try (PrintWriter w = writer(out, "export-complete.txt")) {
            w.println("program=" + currentProgram.getName());
            w.println("language=" + currentProgram.getLanguageID());
            w.println("image_base=" + currentProgram.getImageBase());
            w.println("function_count=" + fm.getFunctionCount());
            w.println("decompilation_attempts=" + chosen.size());
        }
        println("STATIC_EVIDENCE_COMPLETE " + currentProgram.getName());
    }
}
