package samples;

import java.security.SecureRandom;
import java.util.Random;

class InsecureRandomSamples {

    // --- Noncompliant: Random in security context (CRITICAL) ---

    String generateToken() {
        long token = new Random().nextLong(); // Noncompliant
        return Long.toHexString(token);
    }

    byte[] generateSalt() {
        byte[] salt = new byte[16];
        new Random().nextBytes(salt); // Noncompliant
        return salt;
    }

    String generateSessionId() {
        return String.valueOf(Math.random()); // Noncompliant
    }

    // --- Noncompliant: fixed-seed SecureRandom (CRITICAL, always) ---

    byte[] fixedSeedRandom() {
        SecureRandom sr = new SecureRandom(new byte[]{1, 2, 3}); // Noncompliant
        byte[] nonce = new byte[12];
        sr.nextBytes(nonce);
        return nonce;
    }

    // --- Compliant: no security context (skip) ---

    int rollDice() {
        return new Random().nextInt(6) + 1; // Compliant — game logic
    }

    double randomUiOffset() {
        return Math.random() * 100; // Compliant — UI, no security context
    }

    // --- Compliant: proper SecureRandom ---

    byte[] secureNonce() {
        SecureRandom sr = new SecureRandom();
        byte[] nonce = new byte[12];
        sr.nextBytes(nonce); // Compliant
        return nonce;
    }
}
