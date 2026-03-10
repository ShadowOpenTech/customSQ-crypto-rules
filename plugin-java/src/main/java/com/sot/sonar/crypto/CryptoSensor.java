package com.sot.sonar.crypto;

import org.sonar.api.batch.fs.FilePredicates;
import org.sonar.api.batch.fs.InputFile;
import org.sonar.api.batch.sensor.Sensor;
import org.sonar.api.batch.sensor.SensorContext;
import org.sonar.api.batch.sensor.SensorDescriptor;
import org.sonar.api.batch.sensor.issue.NewIssue;
import org.sonar.api.batch.sensor.issue.NewIssueLocation;
import org.sonar.api.rule.RuleKey;
import org.sonar.api.utils.log.Logger;
import org.sonar.api.utils.log.Loggers;

import java.io.IOException;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Regex-based fallback sensor for detecting weak cryptographic patterns in Java.
 *
 * This sensor uses only sonar-plugin-api types (no sonar-java dependency) so it
 * runs reliably in SonarQube's Phase-1 plugin loading even when sonar-java's
 * CheckRegistrar is not yet available.
 *
 * Covers the same three rules as the AST-based checks:
 *   crypto:WeakHashAlgorithm
 *   crypto:InsecureRandom
 *   crypto:WeakPasswordHash
 */
public class CryptoSensor implements Sensor {

    private static final Logger LOG = Loggers.get(CryptoSensor.class);

    private static final String REPOSITORY = CryptoRulesDefinition.REPOSITORY_KEY;
    private static final String RULE_WEAK_HASH    = "WeakHashAlgorithm";
    private static final String RULE_INSEC_RANDOM = "InsecureRandom";
    private static final String RULE_WEAK_PWD     = "WeakPasswordHash";

    // ── WeakHashAlgorithm ──────────────────────────────────────────────────────

    /** MessageDigest.getInstance("MD5"|"SHA-1"|"SHA1"|"SHA"|"SHA-0"|"MD2"|"MD4") */
    private static final Pattern MD_WEAK = Pattern.compile(
        "MessageDigest\\.getInstance\\s*\\(\\s*\"(MD[245]|SHA-?[01]|SHA0|SHA_1|SHA)\"\\s*\\)",
        Pattern.CASE_INSENSITIVE);

    /** DigestUtils.(md2|md5|sha|sha1|crc32) — including *Hex variants */
    private static final Pattern DIGEST_UTILS_WEAK = Pattern.compile(
        "DigestUtils\\.(md2|md2hex|md5|md5hex|sha(?!256|384|512|3)|sha1|sha1hex|shahex|crc32)\\s*\\(",
        Pattern.CASE_INSENSITIVE);

    /** Hashing.(md5|sha1|crc32)() */
    private static final Pattern GUAVA_HASHING_WEAK = Pattern.compile(
        "Hashing\\.(md5|sha1|crc32)\\s*\\(\\s*\\)",
        Pattern.CASE_INSENSITIVE);

    /** new MD5Digest()|SHA1Digest()|MD4Digest()|MD2Digest() */
    private static final Pattern BC_WEAK_DIGEST = Pattern.compile(
        "new\\s+(MD5Digest|SHA1Digest|MD4Digest|MD2Digest)\\s*\\(");

    // ── InsecureRandom ─────────────────────────────────────────────────────────

    /** new Random() */
    private static final Pattern NEW_RANDOM = Pattern.compile(
        "new\\s+Random\\s*\\(\\s*\\)");

    /** Math.random() */
    private static final Pattern MATH_RANDOM = Pattern.compile(
        "Math\\.random\\s*\\(\\s*\\)");

    /** new SecureRandom(<any arguments>) — fixed seed */
    private static final Pattern SECURE_RANDOM_WITH_SEED = Pattern.compile(
        "new\\s+SecureRandom\\s*\\(([^)])");

    /** sr.setSeed(<constant>) */
    private static final Pattern SET_SEED = Pattern.compile(
        "\\.setSeed\\s*\\(");

    // ── WeakPasswordHash ───────────────────────────────────────────────────────

    /** DigestUtils.*(passwordVar) where first arg is a password-named identifier */
    private static final Pattern DIGEST_ON_PWD_VAR = Pattern.compile(
        "DigestUtils\\.\\w+\\s*\\(\\s*(password|passwd|pwd|credentials?|userpassword)\\b",
        Pattern.CASE_INSENSITIVE);

    /** .digest(passwordVar) or .digest(passwordVar.getBytes()) */
    private static final Pattern MD_DIGEST_ON_PWD = Pattern.compile(
        "\\.digest\\s*\\(\\s*(password|passwd|pwd|credentials?|userpassword)\\b",
        Pattern.CASE_INSENSITIVE);

    /** Hashing.*().hashString(passwordVar, ...) */
    private static final Pattern HASHING_ON_PWD = Pattern.compile(
        "Hashing\\.\\w+\\s*\\(\\s*\\)\\.hashString\\s*\\(\\s*(password|passwd|pwd|credentials?|userpassword)\\b",
        Pattern.CASE_INSENSITIVE);

    /** new PBEKeySpec(pw, salt, iterCount, ...) — iteration count is 3rd arg */
    private static final Pattern PBKDF2_SPEC = Pattern.compile(
        "new\\s+PBEKeySpec\\s*\\(");

    private static final int PBKDF2_MIN_ITERATIONS = 600_000;

    // ── Context keywords ───────────────────────────────────────────────────────

    private static final List<String> SECURITY_KEYWORDS = List.of(
        "password", "passwd", "pwd",
        "auth", "authenticate", "login",
        "token", "secret", "credential", "credentials",
        "session", "encrypt", "decrypt", "cipher",
        "sign", "verify", "hmac", "salt", "nonce", "apikey", "key"
    );

    private static final List<String> NON_SECURITY_KEYWORDS = List.of(
        "etag", "cache", "checksum", "fingerprint",
        "uuid", "dedup", "deduplicate", "slug", "filename"
    );

    // ── Method-declaration scanner ─────────────────────────────────────────────

    private static final Pattern METHOD_DECL = Pattern.compile(
        "(?:public|private|protected|static|final|\\s)+\\s+(\\w+)\\s+(\\w+)\\s*\\(([^)]*)\\)");

    // ══════════════════════════════════════════════════════════════════════════
    // Sensor API
    // ══════════════════════════════════════════════════════════════════════════

    @Override
    public void describe(SensorDescriptor descriptor) {
        descriptor
            .name("Custom Crypto Rules (regex sensor)")
            .onlyOnLanguage("java");
    }

    @Override
    public void execute(SensorContext context) {
        boolean weakHashActive    = isActive(context, RULE_WEAK_HASH);
        boolean insecRandomActive = isActive(context, RULE_INSEC_RANDOM);
        boolean weakPwdActive     = isActive(context, RULE_WEAK_PWD);

        if (!weakHashActive && !insecRandomActive && !weakPwdActive) {
            LOG.debug("CryptoSensor: no crypto rules are active, skipping.");
            return;
        }

        FilePredicates p = context.fileSystem().predicates();
        Iterable<InputFile> javaFiles = context.fileSystem().inputFiles(
            p.and(p.hasLanguage("java"), p.hasType(InputFile.Type.MAIN)));

        for (InputFile file : javaFiles) {
            try {
                analyseFile(context, file, weakHashActive, insecRandomActive, weakPwdActive);
            } catch (IOException e) {
                LOG.warn("CryptoSensor: could not read file {}: {}", file, e.getMessage());
            }
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    // Per-file analysis
    // ══════════════════════════════════════════════════════════════════════════

    private void analyseFile(SensorContext ctx, InputFile file,
                             boolean weakHash, boolean insecRandom, boolean weakPwd)
            throws IOException {

        String content = file.contents();
        String[] lines = content.split("\n", -1);

        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            int lineNo = i + 1;

            if (weakHash) {
                checkWeakHash(ctx, file, lines, lineNo, line);
            }
            if (insecRandom) {
                checkInsecureRandom(ctx, file, lines, lineNo, line);
            }
            if (weakPwd) {
                checkWeakPasswordHash(ctx, file, lines, lineNo, line);
            }
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    // WeakHashAlgorithm
    // ══════════════════════════════════════════════════════════════════════════

    private void checkWeakHash(SensorContext ctx, InputFile file,
                               String[] lines, int lineNo, String line) {

        boolean matched = MD_WEAK.matcher(line).find()
            || DIGEST_UTILS_WEAK.matcher(line).find()
            || GUAVA_HASHING_WEAK.matcher(line).find()
            || BC_WEAK_DIGEST.matcher(line).find();

        if (!matched) return;

        // Skip if method/param context is non-security (etag, cache, checksum…)
        MethodContext mc = findEnclosingMethod(lines, lineNo - 1);
        if (mc != null && mc.isNonSecurity()) return;

        String algo = extractWeakAlgo(line);
        String msg = String.format(
            "`%s` is a broken or weak hash algorithm and must not be used for cryptographic purposes. "
                + "Use `SHA-256` or stronger.", algo);

        report(ctx, file, lineNo, RULE_WEAK_HASH, msg);
    }

    private String extractWeakAlgo(String line) {
        Matcher m = MD_WEAK.matcher(line);
        if (m.find()) return m.group(1);
        m = BC_WEAK_DIGEST.matcher(line);
        if (m.find()) return m.group(1);
        m = GUAVA_HASHING_WEAK.matcher(line);
        if (m.find()) return "Hashing." + m.group(1) + "()";
        m = DIGEST_UTILS_WEAK.matcher(line);
        if (m.find()) return "DigestUtils." + m.group(1);
        return "weak algorithm";
    }

    // ══════════════════════════════════════════════════════════════════════════
    // InsecureRandom
    // ══════════════════════════════════════════════════════════════════════════

    private void checkInsecureRandom(SensorContext ctx, InputFile file,
                                     String[] lines, int lineNo, String line) {

        // new SecureRandom(seed) — always flag regardless of context
        if (SECURE_RANDOM_WITH_SEED.matcher(line).find()) {
            report(ctx, file, lineNo, RULE_INSEC_RANDOM,
                "`SecureRandom` must not be initialized with a fixed seed — "
                    + "this produces deterministic output. Remove the seed argument.");
            return;
        }

        // setSeed() — always flag
        if (SET_SEED.matcher(line).find()) {
            report(ctx, file, lineNo, RULE_INSEC_RANDOM,
                "`SecureRandom.setSeed()` with a constant value produces deterministic output.");
            return;
        }

        // new Random() or Math.random() — only flag in security context
        boolean isRandom = NEW_RANDOM.matcher(line).find()
            || MATH_RANDOM.matcher(line).find();
        if (!isRandom) return;

        MethodContext mc = findEnclosingMethod(lines, lineNo - 1);
        boolean inSecurityContext = false;

        if (mc != null) {
            inSecurityContext = mc.isSecurity();
        }

        // Also check if the line itself has a variable name with security keyword
        if (!inSecurityContext) {
            inSecurityContext = lineContainsSecurityKeyword(line);
        }

        if (inSecurityContext) {
            boolean isMath = MATH_RANDOM.matcher(line).find();
            String src = isMath ? "`Math.random()`" : "`java.util.Random`";
            report(ctx, file, lineNo, RULE_INSEC_RANDOM,
                src + " is not cryptographically secure. Use `SecureRandom` for security-sensitive values.");
        }
    }

    private boolean lineContainsSecurityKeyword(String line) {
        String lower = line.toLowerCase(Locale.ROOT);
        for (String kw : SECURITY_KEYWORDS) {
            if (lower.contains(kw)) return true;
        }
        return false;
    }

    // ══════════════════════════════════════════════════════════════════════════
    // WeakPasswordHash
    // ══════════════════════════════════════════════════════════════════════════

    private void checkWeakPasswordHash(SensorContext ctx, InputFile file,
                                       String[] lines, int lineNo, String line) {

        // Sub-pattern A: DigestUtils/MessageDigest on password variable
        if (DIGEST_ON_PWD_VAR.matcher(line).find()
                || MD_DIGEST_ON_PWD.matcher(line).find()
                || HASHING_ON_PWD.matcher(line).find()) {
            report(ctx, file, lineNo, RULE_WEAK_PWD,
                "Hash functions must not be used directly for password hashing. "
                    + "Use `Argon2`, `bcrypt`, `scrypt`, or `PBKDF2` with ≥600,000 iterations.");
            return;
        }

        // Sub-pattern B: PBEKeySpec with low iteration count
        if (PBKDF2_SPEC.matcher(line).find()) {
            int iterations = extractPbkdf2Iterations(line);
            if (iterations > 0 && iterations < PBKDF2_MIN_ITERATIONS) {
                report(ctx, file, lineNo, RULE_WEAK_PWD, String.format(
                    "PBKDF2 iteration count of %,d is insufficient. "
                        + "Use at least %,d iterations (OWASP 2025 for PBKDF2-HMAC-SHA256).",
                    iterations, PBKDF2_MIN_ITERATIONS));
            }
        }
    }

    /** Extract the 3rd argument of new PBEKeySpec(pw, salt, iterCount, ...) from a single line. */
    private int extractPbkdf2Iterations(String line) {
        // Find "new PBEKeySpec(" and then parse comma-separated args
        int start = line.indexOf("new PBEKeySpec(");
        if (start < 0) {
            start = line.indexOf("new PBEKeySpec (");
        }
        if (start < 0) return -1;

        int parenStart = line.indexOf('(', start);
        if (parenStart < 0) return -1;

        // Collect up to closing paren (simple, no nested parens in practice here)
        int depth = 0;
        StringBuilder args = new StringBuilder();
        for (int i = parenStart; i < line.length(); i++) {
            char c = line.charAt(i);
            if (c == '(') depth++;
            else if (c == ')') { depth--; if (depth == 0) break; }
            args.append(c);
        }
        // args now looks like "(password, salt, 10_000, 256"
        String inner = args.toString().substring(1); // strip leading '('
        String[] parts = inner.split(",");
        if (parts.length < 3) return -1;

        String iterStr = parts[2].trim().replace("_", "").replaceAll("[^\\d]", "");
        if (iterStr.isEmpty()) return -1;
        try {
            return Integer.parseInt(iterStr);
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    // Context detection
    // ══════════════════════════════════════════════════════════════════════════

    private MethodContext findEnclosingMethod(String[] lines, int zeroBasedLine) {
        // Scan backwards to find the nearest method declaration
        for (int i = zeroBasedLine; i >= 0; i--) {
            Matcher m = METHOD_DECL.matcher(lines[i]);
            if (m.find()) {
                String methodName = m.group(2);
                String params     = m.group(3);
                return new MethodContext(methodName, params);
            }
        }
        return null;
    }

    private static final class MethodContext {
        private final String methodName;
        private final String params;

        MethodContext(String methodName, String params) {
            this.methodName = methodName.toLowerCase(Locale.ROOT);
            this.params     = params.toLowerCase(Locale.ROOT);
        }

        boolean isSecurity() {
            for (String kw : SECURITY_KEYWORDS) {
                if (methodName.contains(kw) || params.contains(kw)) return true;
            }
            return false;
        }

        boolean isNonSecurity() {
            for (String kw : NON_SECURITY_KEYWORDS) {
                if (methodName.contains(kw) || params.contains(kw)) return true;
            }
            return false;
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    // Helpers
    // ══════════════════════════════════════════════════════════════════════════

    private boolean isActive(SensorContext context, String ruleKey) {
        return context.activeRules().find(RuleKey.of(REPOSITORY, ruleKey)) != null;
    }

    private void report(SensorContext ctx, InputFile file, int line,
                        String ruleKey, String message) {
        try {
            NewIssue issue = ctx.newIssue()
                .forRule(RuleKey.of(REPOSITORY, ruleKey));
            NewIssueLocation loc = issue.newLocation()
                .on(file)
                .at(file.selectLine(line))
                .message(message);
            issue.at(loc).save();
        } catch (Exception e) {
            LOG.warn("CryptoSensor: failed to report issue at {}:{} — {}", file, line, e.getMessage());
        }
    }
}
