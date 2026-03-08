package samples;

import java.security.MessageDigest;
import java.security.spec.PBEKeySpec;
import org.apache.commons.codec.digest.DigestUtils;

class WeakPasswordHashSamples {

    // --- Noncompliant: Sub-pattern A — general hash on password variable ---

    void storePassword(String password) throws Exception {
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(password.getBytes()); // Noncompliant
    }

    String hashPasswd(String passwd) throws Exception {
        return DigestUtils.sha1Hex(passwd); // Noncompliant
    }

    byte[] hashCredentials(byte[] credentials) throws Exception {
        return MessageDigest.getInstance("SHA-512").digest(credentials); // Noncompliant
    }

    // Even MD5 on password (would also fire WeakHashAlgorithm, but still caught here)
    String legacyHash(String pwd) {
        return DigestUtils.md5Hex(pwd); // Noncompliant
    }

    // --- Noncompliant: Sub-pattern B — PBKDF2 with low iteration count ---

    byte[] deriveKey(char[] password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, salt, 10_000, 256); // Noncompliant — < 600,000
        return null;
    }

    byte[] deriveKeyBorderline(char[] password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, salt, 599_999, 256); // Noncompliant — < 600,000
        return null;
    }

    // --- Noncompliant: Sub-pattern C — unsalted hash on password ---

    byte[] unsaltedHash(String password) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(password.getBytes()); // Noncompliant — no salt
    }

    // --- Compliant ---

    // PBKDF2 with sufficient iterations
    byte[] goodDerive(char[] password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, salt, 600_000, 256); // Compliant
        return null;
    }

    // Non-password variable — not triggered
    byte[] hashFilename(String filename) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(filename.getBytes()); // Compliant — not a password
    }
}
