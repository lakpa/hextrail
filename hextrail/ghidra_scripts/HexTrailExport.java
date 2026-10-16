// Export Ghidra decompiler results using HexTrail's bounded JSON contract.
// @category HexTrail

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class HexTrailExport extends GhidraScript {
    private static final int MAX_FUNCTIONS = 100000;
    private static final int MAX_WARNINGS = 10000;
    private static final int MAX_NAME_CHARS = 4096;
    private static final int MAX_SIGNATURE_CHARS = 32768;
    private static final int MAX_PSEUDOCODE_CHARS = 2000000;
    private static final int MAX_TOTAL_PSEUDOCODE_CHARS = 8 * 1024 * 1024;

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 3) {
            throw new IllegalArgumentException(
                "Expected output path, binary SHA-256 and per-function timeout"
            );
        }
        Path output = Paths.get(args[0]).toAbsolutePath().normalize();
        String expectedSha256 = args[1].toLowerCase(Locale.ROOT);
        int timeoutSeconds = Integer.parseInt(args[2]);
        if (timeoutSeconds <= 0) {
            throw new IllegalArgumentException("Per-function timeout must be positive");
        }

        String actualSha256 = currentProgram.getExecutableSHA256();
        if (actualSha256 == null || !expectedSha256.equals(actualSha256.toLowerCase(Locale.ROOT))) {
            throw new IllegalStateException("Imported program SHA-256 does not match HexTrail input");
        }

        List<String> warnings = new ArrayList<>();
        StringBuilder functionsJson = new StringBuilder();
        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(true);
        decompiler.setSimplificationStyle("decompile");
        if (!decompiler.openProgram(currentProgram)) {
            decompiler.dispose();
            throw new IllegalStateException("Could not initialize Ghidra's decompiler");
        }

        int count = 0;
        int totalPseudocode = 0;
        boolean pseudocodeBudgetWarningAdded = false;
        try {
            FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
            while (iterator.hasNext()) {
                monitor.checkCancelled();
                Function function = iterator.next();
                if (function.isExternal()) {
                    continue;
                }
                if (count >= MAX_FUNCTIONS) {
                    addWarning(warnings, "Function export stopped at the 100,000-entry limit.");
                    break;
                }

                String pseudocode = "";
                String signature = function.getPrototypeString(false, true);
                try {
                    DecompileResults results =
                        decompiler.decompileFunction(function, timeoutSeconds, monitor);
                    DecompiledFunction decompiled = results.getDecompiledFunction();
                    if (results.decompileCompleted() && decompiled != null) {
                        pseudocode = safe(decompiled.getC());
                        signature = safe(decompiled.getSignature());
                        String message = safe(results.getErrorMessage()).trim();
                        if (!message.isEmpty()) {
                            addWarning(warnings, warningFor(function, message));
                        }
                    }
                    else {
                        String message = safe(results.getErrorMessage()).trim();
                        if (message.isEmpty()) {
                            message = results.isTimedOut()
                                ? "per-function timeout"
                                : "no decompiler output";
                        }
                        addWarning(warnings, warningFor(function, message));
                    }
                }
                catch (Exception exception) {
                    addWarning(warnings, warningFor(function, safe(exception.getMessage())));
                }

                if (pseudocode.length() > MAX_PSEUDOCODE_CHARS) {
                    pseudocode = pseudocode.substring(0, MAX_PSEUDOCODE_CHARS);
                    addWarning(warnings, warningFor(function, "pseudocode truncated"));
                }
                int remaining = MAX_TOTAL_PSEUDOCODE_CHARS - totalPseudocode;
                if (pseudocode.length() > remaining) {
                    pseudocode = pseudocode.substring(0, Math.max(0, remaining));
                    if (!pseudocodeBudgetWarningAdded) {
                        addWarning(warnings, "Total pseudocode output reached its export limit.");
                        pseudocodeBudgetWarningAdded = true;
                    }
                }
                totalPseudocode += pseudocode.length();

                if (count > 0) {
                    functionsJson.append(',');
                }
                appendFunction(functionsJson, function, signature, pseudocode);
                count++;
            }
        }
        finally {
            decompiler.dispose();
        }

        String processor = currentProgram.getLanguage().getProcessor().toString();
        String architecture = processor.equalsIgnoreCase("AARCH64") ? "AArch64" : processor;
        StringBuilder report = new StringBuilder(functionsJson.length() + 4096);
        report.append("{\"schema\":\"hextrail.decompilation.v1\",\"binary\":{");
        report.append("\"sha256\":");
        appendJsonString(report, expectedSha256);
        report.append(",\"architecture\":");
        appendJsonString(report, architecture);
        report.append("},\"provider\":{\"name\":\"Ghidra\",\"version\":");
        appendJsonString(report, getGhidraVersion());
        report.append("},\"functions\":[").append(functionsJson).append("],\"warnings\":[");
        for (int index = 0; index < warnings.size(); index++) {
            if (index > 0) {
                report.append(',');
            }
            appendJsonString(report, warnings.get(index));
        }
        report.append("]}");
        writeAtomically(output, report.toString());
    }

    private static void appendFunction(
            StringBuilder json, Function function, String signature, String pseudocode) {
        json.append("{\"address\":");
        json.append(Long.toUnsignedString(function.getEntryPoint().getOffset()));
        json.append(",\"size\":").append(function.getBody().getNumAddresses());
        json.append(",\"name\":");
        appendJsonString(json, limit(safe(function.getName()), MAX_NAME_CHARS));
        json.append(",\"signature\":");
        appendJsonString(json, limit(safe(signature), MAX_SIGNATURE_CHARS));
        json.append(",\"pseudocode\":");
        appendJsonString(json, pseudocode);
        json.append(",\"boundary_source\":");
        String source = function.getSymbol() == null
            ? "Ghidra analysis"
            : "Ghidra " + function.getSymbol().getSource().name().toLowerCase(Locale.ROOT);
        appendJsonString(json, source);
        json.append('}');
    }

    private static String warningFor(Function function, String message) {
        String detail = message == null || message.trim().isEmpty()
            ? "unknown decompiler error"
            : message.trim();
        return limit("0x" + function.getEntryPoint() + " " + function.getName() + ": " + detail, 4096);
    }

    private static void addWarning(List<String> warnings, String warning) {
        if (warnings.size() < MAX_WARNINGS) {
            warnings.add(limit(safe(warning), 4096));
        }
    }

    private static String safe(String value) {
        return value == null ? "" : value;
    }

    private static String limit(String value, int maximum) {
        return value.length() <= maximum ? value : value.substring(0, maximum);
    }

    private static void appendJsonString(StringBuilder json, String value) {
        json.append('"');
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            switch (character) {
                case '"': json.append("\\\""); break;
                case '\\': json.append("\\\\"); break;
                case '\b': json.append("\\b"); break;
                case '\f': json.append("\\f"); break;
                case '\n': json.append("\\n"); break;
                case '\r': json.append("\\r"); break;
                case '\t': json.append("\\t"); break;
                default:
                    if (character < 0x20) {
                        json.append(String.format(Locale.ROOT, "\\u%04x", (int) character));
                    }
                    else {
                        json.append(character);
                    }
            }
        }
        json.append('"');
    }

    private static void writeAtomically(Path output, String contents) throws IOException {
        Path temporary = output.resolveSibling(output.getFileName().toString() + ".tmp");
        Files.write(
            temporary,
            contents.getBytes(StandardCharsets.UTF_8),
            StandardOpenOption.CREATE,
            StandardOpenOption.TRUNCATE_EXISTING,
            StandardOpenOption.WRITE
        );
        try {
            Files.move(
                temporary,
                output,
                StandardCopyOption.ATOMIC_MOVE,
                StandardCopyOption.REPLACE_EXISTING
            );
        }
        catch (AtomicMoveNotSupportedException exception) {
            Files.move(temporary, output, StandardCopyOption.REPLACE_EXISTING);
        }
    }
}
