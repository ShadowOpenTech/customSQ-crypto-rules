package samples;

import java.security.MessageDigest;
import org.apache.commons.codec.digest.DigestUtils;
import com.google.common.hash.Hashing;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;

class WeakHashAlgorithmSamples {

    // --- Noncompliant: security context (CRITICAL) ---

    void hashToken(String token) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5"); // Noncompliant
        md.digest(token.getBytes());
    }

    String hashPassword(String password) {
        return DigestUtils.md5Hex(password); // Noncompliant
    }

    byte[] signData(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-1").digest(data); // Noncompliant
    }

    // --- Noncompliant: neutral context (MAJOR) ---

    void someMethod() throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5"); // Noncompliant
    }

    byte[] compute(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA1").digest(data); // Noncompliant
    }

    // BouncyCastle — always noncompliant
    void bouncyCastle() {
        MD5Digest d1 = new MD5Digest(); // Noncompliant
        SHA1Digest d2 = new SHA1Digest(); // Noncompliant
    }

    // --- Compliant: non-security context (skip) ---

    String computeEtag(byte[] body) {
        return DigestUtils.md5Hex(body); // Compliant — etag context
    }

    String buildCacheKey(String url) {
        return Hashing.md5().hashString(url, java.nio.charset.StandardCharsets.UTF_8).toString(); // Compliant — cache context
    }

    // --- Compliant: strong algorithm ---

    byte[] safeHash(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(data); // Compliant
    }
}
