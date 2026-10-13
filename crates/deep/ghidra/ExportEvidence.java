// ByteBouncer evidence export for Ghidra headless mode.
//
// Read-only: inspects the imported program and writes one bounded JSON
// document. It never modifies the program beyond Ghidra's own auto-analysis
// and never touches the network.
//
// Script arguments: <out.json> <maxDecompiledFunctions> <maxCharsPerFunction>
//                   <decompileTimeoutSecs>
//@category ByteBouncer
//@runtime Java

import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Pattern;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SymbolTable;

public class ExportEvidence extends HeadlessScript {
    static final int MAX_FUNCTIONS_LISTED = 5000;
    static final int MAX_EDGES_PER_FUNCTION = 15;
    static final int MAX_IMPORTS = 3000;
    static final int MAX_API_USES = 300;
    static final int MAX_CALLERS_PER_API = 25;
    static final int MAX_CHAINS_PER_API = 5;
    static final int MAX_CHAIN_DEPTH = 10;
    static final int MAX_BFS_NODES = 3000;
    static final int MAX_STRINGS = 600;
    static final int MAX_STRING_CHARS = 300;
    static final int MAX_REFS_PER_STRING = 10;
    static final int MAX_TOTAL_DECOMPILED_CHARS = 400_000;

    static final String[][] API_CATEGORIES = {
        {"network", "socket|connect|send|sendto|sendmsg|recv|recvfrom|getaddrinfo|gethostbyname2?|"
            + "WSAStartup|WSASocket[AW]?|WSAConnect|WSASend(To)?|WSARecv(From)?|Internet[A-Za-z]+|"
            + "HttpOpenRequest[AW]?|HttpSendRequest(Ex)?[AW]?|WinHttp[A-Za-z]+|curl_[a-z_]+|"
            + "SSL_connect|SSL_write|g_socket_[a-z_]+|soup_session_[a-z_]+|NSURLSession|CFNetwork[A-Za-z]*"},
        {"download", "URLDownloadToFile[AW]?|URLDownloadToCacheFile[AW]?|URLOpenStream[AW]?|BITS[A-Za-z]*"},
        {"process", "execve|execv|execvp|execvpe|execl|execlp|execle|system|popen|posix_spawnp?|fork|vfork|"
            + "CreateProcess(AsUser|WithLogon|WithToken)?[AW]?|ShellExecute(Ex)?[AW]?|WinExec"},
        {"injection", "ptrace|process_vm_writev|WriteProcessMemory|VirtualAllocEx|CreateRemoteThread(Ex)?|"
            + "NtWriteVirtualMemory|NtCreateThreadEx|SetThreadContext|QueueUserAPC|RtlCreateUserThread|"
            + "task_for_pid|mach_vm_write"},
        {"input_capture", "SetWindowsHookEx[AW]?|GetAsyncKeyState|GetKeyboardState|GetKeyState|"
            + "RegisterRawInputDevices|XQueryKeymap|XGrabKeyboard|XRecordEnableContext(Async)?|CGEventTapCreate"},
        {"clipboard", "GetClipboardData|OpenClipboard|SetClipboardData|gtk_clipboard_[a-z_]+|XConvertSelection|"
            + "XGetSelectionOwner"},
        {"screen_capture", "BitBlt|GetWindowDC|CreateCompatibleBitmap|PrintWindow|XGetImage|XShmGetImage|"
            + "CGWindowListCreateImage|CGDisplayCreateImage"},
        {"registry_write", "RegSetValue(Ex)?[AW]?|RegCreateKey(Ex)?[AW]?|RegDeleteKey(Ex)?[AW]?|"
            + "RegDeleteValue[AW]?|RegSetKeyValue[AW]?"},
        {"file_write", "WriteFile|CreateFile[AW]|MoveFile(Ex)?[AW]?|CopyFile(Ex)?[AW]?|DeleteFile[AW]?|"
            + "rename|renameat2?|unlink|unlinkat|chmod|fchmod|creat"},
        {"service", "CreateService[AW]?|ChangeServiceConfig2?[AW]?|StartService[AW]?"},
        {"crypto", "Crypt[A-Z][A-Za-z]+|BCrypt[A-Za-z]+|EVP_[A-Za-z_0-9]+|AES_[a-z_]+|RAND_bytes|"
            + "gcry_[a-z_]+|mbedtls_[a-z_0-9]+|CCCrypt[A-Za-z]*"},
        {"dynamic_load", "dlopen|dlmopen|dlsym|dlvsym|LoadLibrary(Ex)?[AW]?|GetProcAddress|LdrLoadDll|"
            + "LdrGetProcedureAddress"},
    };

    static final Pattern URL = Pattern.compile("(?i)\\b(?:https?|wss?|ftp)://[^\\s\"'<>]{3,}");
    static final Pattern DOMAIN = Pattern.compile(
        "(?i)^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+(?:com|net|org|io|dev|app|cloud|co|info|biz|ru|cn|"
            + "de|uk|us|xyz|top|me|ai|gg|so|sh|tk|cc|pw|su|invalid|example|test|local)$");
    static final Pattern PATH = Pattern.compile(
        "^(?:/(?:etc|home|root|tmp|var|usr|proc|dev|Library|Users|Applications|opt)/|~/|[A-Za-z]:\\\\|%[A-Za-z]+%|"
            + "\\\\\\\\)[^\\n]{1,}");
    static final Pattern REGISTRY = Pattern.compile("(?i)^(?:HKEY_|HKLM\\\\|HKCU\\\\|Software\\\\|SYSTEM\\\\CurrentControlSet)");

    final List<Pattern[]> compiled = new ArrayList<>();
    final List<String> categoryNames = new ArrayList<>();
    final Set<Function> entryFunctions = new HashSet<>();
    final Map<Function, Integer> relevance = new HashMap<>();

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            throw new IllegalArgumentException("usage: ExportEvidence <out.json> [maxDecomp] [maxChars] [timeoutSecs]");
        }
        String outPath = args[0];
        int maxDecompiled = args.length > 1 ? Integer.parseInt(args[1]) : 20;
        int maxChars = args.length > 2 ? Integer.parseInt(args[2]) : 4000;
        int decompTimeout = args.length > 3 ? Integer.parseInt(args[3]) : 30;

        for (String[] c : API_CATEGORIES) {
            categoryNames.add(c[0]);
            compiled.add(new Pattern[] {Pattern.compile("^(?:" + c[1] + ")$")});
        }

        Json j = new Json();
        j.beginObject();
        j.key("schema").value("bytebouncer-ghidra-export/1");
        boolean timedOut = false;
        try {
            timedOut = analysisTimeoutOccurred();
        }
        catch (Throwable t) {
            // Not running headless or API unavailable.
        }
        j.key("analysis_timed_out").value(timedOut);

        collectEntryFunctions();
        writeProgram(j);
        writeFunctions(j);
        writeImports(j);
        writeApiUses(j);
        writeStrings(j);
        writeDecompiled(j, maxDecompiled, maxChars, decompTimeout);
        j.key("cancelled").value(monitor.isCancelled());
        j.endObject();

        try (Writer w = new BufferedWriter(
            new OutputStreamWriter(new FileOutputStream(outPath), StandardCharsets.UTF_8))) {
            w.write(j.toString());
        }
    }

    // ---- helpers -------------------------------------------------------

    static String normalize(String name) {
        String n = name;
        if (n.startsWith("__imp_")) {
            n = n.substring(6);
        }
        int at = n.indexOf('@');
        if (at > 0) {
            n = n.substring(0, at);
        }
        while (n.startsWith("_") && n.length() > 1) {
            n = n.substring(1);
        }
        return n;
    }

    String categoryOf(String name) {
        String n = normalize(name);
        for (int i = 0; i < compiled.size(); i++) {
            if (compiled.get(i)[0].matcher(n).matches()) {
                return categoryNames.get(i);
            }
        }
        return null;
    }

    static String label(Function f) {
        return f.getName() + "@" + f.getEntryPoint().toString();
    }

    void collectEntryFunctions() {
        SymbolTable st = currentProgram.getSymbolTable();
        AddressIterator it = st.getExternalEntryPointIterator();
        while (it.hasNext()) {
            Function f = getFunctionAt(it.next());
            if (f != null) {
                entryFunctions.add(f);
            }
        }
        for (String n : new String[] {"main", "wmain", "WinMain", "wWinMain", "DllMain", "_start", "entry",
            "JNI_OnLoad", "DllRegisterServer", "ServiceMain"}) {
            for (Function f : getGlobalFunctions(n)) {
                if (!f.isExternal()) {
                    entryFunctions.add(f);
                }
            }
        }
        // The program entry stub hands main (and init/fini) to the C runtime by
        // address (`__libc_start_main(main, ...)`), not by a call: treat
        // functions whose address the entry stub takes as entry points too.
        // This matters for stripped binaries where main has no symbol.
        for (Function f : new ArrayList<>(entryFunctions)) {
            if (!f.getName().equals("_start") && !f.getName().equals("entry")) {
                continue;
            }
            AddressIterator src = currentProgram.getReferenceManager().getReferenceSourceIterator(f.getBody(), true);
            int n = 0;
            while (src.hasNext() && n++ < 200) {
                for (Reference r : getReferencesFrom(src.next())) {
                    if (r.getReferenceType().isCall()) {
                        continue;
                    }
                    Function target = getFunctionAt(r.getToAddress());
                    if (target != null && !target.isExternal() && !target.isThunk()) {
                        entryFunctions.add(target);
                    }
                }
            }
        }
    }

    /** Non-thunk callers, looking through thunks (PLT stubs, import jumps). */
    Set<Function> realCallers(Function f) {
        Set<Function> out = new LinkedHashSet<>();
        Deque<Function> work = new ArrayDeque<>();
        Set<Function> seen = new HashSet<>();
        work.add(f);
        while (!work.isEmpty() && seen.size() < 200) {
            Function cur = work.poll();
            if (!seen.add(cur)) {
                continue;
            }
            for (Function c : cur.getCallingFunctions(monitor)) {
                if (c.isThunk()) {
                    work.add(c);
                }
                else {
                    out.add(c);
                }
            }
            // Thunks pointing at this function are callers too.
            Address[] thunks = cur.getFunctionThunkAddresses(true);
            if (thunks != null) {
                for (Address a : thunks) {
                    Function t = getFunctionAt(a);
                    if (t != null) {
                        work.add(t);
                    }
                }
            }
        }
        return out;
    }

    /** Shortest caller chain from an entry function down to `start` (inclusive), or null. */
    List<Function> chainToEntry(Function start) {
        if (entryFunctions.contains(start)) {
            return new ArrayList<>(List.of(start));
        }
        Map<Function, Function> parentOf = new HashMap<>();
        Map<Function, Integer> depth = new HashMap<>();
        Deque<Function> q = new ArrayDeque<>();
        q.add(start);
        depth.put(start, 0);
        int visited = 0;
        while (!q.isEmpty() && visited++ < MAX_BFS_NODES && !monitor.isCancelled()) {
            Function cur = q.poll();
            int d = depth.get(cur);
            if (d >= MAX_CHAIN_DEPTH) {
                continue;
            }
            for (Function caller : realCallers(cur)) {
                if (depth.containsKey(caller)) {
                    continue;
                }
                depth.put(caller, d + 1);
                parentOf.put(caller, cur);
                if (entryFunctions.contains(caller)) {
                    List<Function> chain = new ArrayList<>();
                    Function x = caller;
                    while (x != null) {
                        chain.add(x);
                        x = parentOf.get(x);
                    }
                    return chain; // entry first, start last
                }
                q.add(caller);
            }
        }
        return null;
    }

    void bump(Function f, int by) {
        relevance.merge(f, by, Integer::sum);
    }

    // ---- sections ------------------------------------------------------

    void writeProgram(Json j) {
        j.key("program").beginObject();
        j.key("name").value(currentProgram.getName());
        j.key("format").value(currentProgram.getExecutableFormat());
        j.key("language").value(currentProgram.getLanguageID().toString());
        j.key("compiler").value(currentProgram.getCompilerSpec().getCompilerSpecID().toString());
        j.key("image_base").value(currentProgram.getImageBase().toString());
        j.key("function_count").value(currentProgram.getFunctionManager().getFunctionCount());
        int ext = 0;
        FunctionIterator ei = currentProgram.getFunctionManager().getExternalFunctions();
        while (ei.hasNext()) {
            ei.next();
            ext++;
        }
        j.key("external_function_count").value(ext);
        j.key("entry_points").beginArray();
        int n = 0;
        for (Function f : entryFunctions) {
            if (n++ >= 50) {
                break;
            }
            j.value(label(f));
        }
        j.endArray();
        j.endObject();
    }

    void writeFunctions(Json j) {
        Listing listing = currentProgram.getListing();
        j.key("functions").beginArray();
        int count = 0;
        boolean truncated = false;
        FunctionIterator it = listing.getFunctions(true);
        while (it.hasNext()) {
            Function f = it.next();
            if (count >= MAX_FUNCTIONS_LISTED || monitor.isCancelled()) {
                truncated = true;
                break;
            }
            count++;
            j.beginObject();
            j.key("name").value(f.getName());
            j.key("address").value(f.getEntryPoint().toString());
            j.key("size").value(f.getBody().getNumAddresses());
            j.key("thunk").value(f.isThunk());
            j.key("entry").value(entryFunctions.contains(f));
            j.key("callees").beginArray();
            int e = 0;
            for (Function c : f.getCalledFunctions(monitor)) {
                if (e++ >= MAX_EDGES_PER_FUNCTION) {
                    break;
                }
                j.value(c.isThunk() && c.getThunkedFunction(true) != null
                    ? c.getThunkedFunction(true).getName() : c.getName());
            }
            j.endArray();
            j.key("callers").beginArray();
            e = 0;
            for (Function c : f.getCallingFunctions(monitor)) {
                if (e++ >= MAX_EDGES_PER_FUNCTION) {
                    break;
                }
                j.value(c.getName());
            }
            j.endArray();
            j.endObject();
        }
        j.endArray();
        j.key("functions_truncated").value(truncated);
    }

    void writeImports(Json j) {
        j.key("imports").beginArray();
        int n = 0;
        FunctionIterator it = currentProgram.getFunctionManager().getExternalFunctions();
        boolean truncated = false;
        while (it.hasNext()) {
            Function f = it.next();
            if (n++ >= MAX_IMPORTS) {
                truncated = true;
                break;
            }
            ExternalLocation loc = f.getExternalLocation();
            j.beginObject();
            j.key("name").value(f.getName());
            j.key("library").value(loc != null ? loc.getLibraryName() : null);
            j.key("category").value(categoryOf(f.getName()));
            j.endObject();
        }
        j.endArray();
        j.key("imports_truncated").value(truncated);
    }

    void writeApiUses(Json j) {
        // Group all functions (external, thunk, or statically linked) by
        // normalized API name.
        Map<String, List<Function>> byApi = new TreeMap<>();
        Map<String, String> catOf = new HashMap<>();
        List<Function> all = new ArrayList<>();
        currentProgram.getFunctionManager().getExternalFunctions().forEach(all::add);
        currentProgram.getFunctionManager().getFunctions(true).forEach(all::add);
        for (Function f : all) {
            String cat = categoryOf(f.getName());
            if (cat == null) {
                continue;
            }
            String api = normalize(f.getName());
            byApi.computeIfAbsent(api, k -> new ArrayList<>()).add(f);
            catOf.put(api, cat);
        }
        j.key("api_uses").beginArray();
        int n = 0;
        boolean truncated = false;
        for (Map.Entry<String, List<Function>> e : byApi.entrySet()) {
            if (monitor.isCancelled()) {
                truncated = true;
                break;
            }
            Set<Function> callers = new LinkedHashSet<>();
            Set<Function> apiFns = new HashSet<>(e.getValue());
            for (Function f : e.getValue()) {
                for (Function c : realCallers(f)) {
                    if (!apiFns.contains(c)) {
                        callers.add(c);
                    }
                }
            }
            if (callers.isEmpty()) {
                continue; // imported but no resolved call site
            }
            if (n++ >= MAX_API_USES) {
                truncated = true;
                break;
            }
            String cat = catOf.get(e.getKey());
            j.beginObject();
            j.key("api").value(e.getKey());
            j.key("category").value(cat);
            j.key("caller_count").value(callers.size());
            j.key("callers").beginArray();
            int c = 0;
            for (Function f : callers) {
                if (c++ >= MAX_CALLERS_PER_API) {
                    break;
                }
                j.value(label(f));
                if (!"crypto".equals(cat)) {
                    bump(f, "file_write".equals(cat) || "dynamic_load".equals(cat) ? 1 : 3);
                }
            }
            j.endArray();
            j.key("chains").beginArray();
            int chains = 0;
            c = 0;
            for (Function f : callers) {
                if (chains >= MAX_CHAINS_PER_API || c++ >= MAX_CALLERS_PER_API) {
                    break;
                }
                List<Function> chain = chainToEntry(f);
                if (chain == null) {
                    continue;
                }
                chains++;
                j.beginArray();
                for (Function x : chain) {
                    j.value(label(x));
                }
                j.value(e.getKey());
                j.endArray();
            }
            j.endArray();
            j.endObject();
        }
        j.endArray();
        j.key("api_uses_truncated").value(truncated);
    }

    String classify(String s) {
        if (URL.matcher(s).find()) {
            return "url";
        }
        if (s.length() <= 253 && DOMAIN.matcher(s).matches()) {
            return "domain";
        }
        if (REGISTRY.matcher(s).find()) {
            return "registry";
        }
        if (PATH.matcher(s).find()) {
            return "path";
        }
        return null;
    }

    Set<Function> referencingFunctions(Address target) {
        Set<Function> out = new LinkedHashSet<>();
        for (Reference r : getReferencesTo(target)) {
            if (out.size() >= MAX_REFS_PER_STRING) {
                break;
            }
            Function f = getFunctionContaining(r.getFromAddress());
            if (f != null) {
                out.add(f);
                continue;
            }
            // One level of indirection: a pointer in data that code references.
            for (Reference r2 : getReferencesTo(r.getFromAddress())) {
                Function g = getFunctionContaining(r2.getFromAddress());
                if (g != null && out.size() < MAX_REFS_PER_STRING) {
                    out.add(g);
                }
            }
        }
        return out;
    }

    void writeStrings(Json j) {
        j.key("strings").beginArray();
        DataIterator it = currentProgram.getListing().getDefinedData(true);
        int n = 0;
        boolean truncated = false;
        while (it.hasNext() && !monitor.isCancelled()) {
            Data d = it.next();
            if (!d.hasStringValue()) {
                continue;
            }
            Object v = d.getValue();
            if (!(v instanceof String)) {
                continue;
            }
            String s = ((String) v).trim();
            String kind = classify(s);
            if (kind == null) {
                continue;
            }
            if (n++ >= MAX_STRINGS) {
                truncated = true;
                break;
            }
            Set<Function> refs = referencingFunctions(d.getAddress());
            for (Function f : refs) {
                bump(f, "url".equals(kind) || "domain".equals(kind) ? 2 : 1);
            }
            boolean cut = s.length() > MAX_STRING_CHARS;
            j.beginObject();
            j.key("value").value(cut ? s.substring(0, MAX_STRING_CHARS) : s);
            j.key("truncated").value(cut);
            j.key("kind").value(kind);
            j.key("address").value(d.getAddress().toString());
            j.key("functions").beginArray();
            for (Function f : refs) {
                j.value(label(f));
            }
            j.endArray();
            j.endObject();
        }
        j.endArray();
        j.key("strings_truncated").value(truncated);
    }

    void writeDecompiled(Json j, int maxFunctions, int maxChars, int timeoutSecs) {
        List<Map.Entry<Function, Integer>> ranked = new ArrayList<>(relevance.entrySet());
        ranked.sort((a, b) -> {
            int c = Integer.compare(b.getValue(), a.getValue());
            return c != 0 ? c : a.getKey().getEntryPoint().compareTo(b.getKey().getEntryPoint());
        });
        j.key("relevant_function_count").value(ranked.size());
        j.key("decompiled").beginArray();
        if (maxFunctions <= 0 || ranked.isEmpty()) {
            j.endArray();
            return;
        }
        DecompInterface ifc = new DecompInterface();
        int total = 0;
        try {
            if (!ifc.openProgram(currentProgram)) {
                j.endArray();
                j.key("decompiler_error").value(ifc.getLastMessage());
                return;
            }
            int n = 0;
            for (Map.Entry<Function, Integer> e : ranked) {
                if (n >= maxFunctions || monitor.isCancelled() || total >= MAX_TOTAL_DECOMPILED_CHARS) {
                    break;
                }
                Function f = e.getKey();
                if (f.isExternal() || f.isThunk()) {
                    continue;
                }
                n++;
                DecompileResults res = ifc.decompileFunction(f, timeoutSecs, monitor);
                j.beginObject();
                j.key("function").value(label(f));
                j.key("relevance").value(e.getValue());
                if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
                    String code = res.getDecompiledFunction().getC();
                    int limit = Math.min(maxChars, MAX_TOTAL_DECOMPILED_CHARS - total);
                    boolean cut = code.length() > limit;
                    if (cut) {
                        code = code.substring(0, Math.max(0, limit));
                    }
                    total += code.length();
                    j.key("code").value(code);
                    j.key("truncated").value(cut);
                }
                else {
                    j.key("error").value(res == null ? "no result"
                        : (res.isTimedOut() ? "decompiler timed out" : String.valueOf(res.getErrorMessage())));
                }
                j.endObject();
            }
        }
        finally {
            ifc.dispose();
        }
        j.endArray();
    }

    // ---- minimal JSON writer --------------------------------------------

    static final class Json {
        private final StringBuilder sb = new StringBuilder();
        private final Deque<Boolean> first = new ArrayDeque<>();
        private boolean afterKey = false;

        private void sep() {
            if (afterKey) {
                afterKey = false;
                return;
            }
            if (!first.isEmpty()) {
                if (first.peek()) {
                    first.pop();
                    first.push(false);
                }
                else {
                    sb.append(',');
                }
            }
        }

        Json beginObject() {
            sep();
            sb.append('{');
            first.push(true);
            return this;
        }

        Json endObject() {
            first.pop();
            sb.append('}');
            return this;
        }

        Json beginArray() {
            sep();
            sb.append('[');
            first.push(true);
            return this;
        }

        Json endArray() {
            first.pop();
            sb.append(']');
            return this;
        }

        Json key(String k) {
            sep();
            str(k);
            sb.append(':');
            afterKey = true;
            return this;
        }

        Json value(String s) {
            sep();
            if (s == null) {
                sb.append("null");
            }
            else {
                str(s);
            }
            return this;
        }

        Json value(long v) {
            sep();
            sb.append(v);
            return this;
        }

        Json value(boolean v) {
            sep();
            sb.append(v);
            return this;
        }

        private void str(String s) {
            sb.append('"');
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                if (c == '"' || c == '\\') {
                    sb.append('\\').append(c);
                }
                else if (c < 0x20 || c > 0x7e) {
                    sb.append(String.format("\\u%04x", (int) c));
                }
                else {
                    sb.append(c);
                }
            }
            sb.append('"');
        }

        @Override
        public String toString() {
            return sb.toString();
        }
    }
}
