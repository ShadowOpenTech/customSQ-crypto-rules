package samples

import java.security.SecureRandom
import java.util.Random

// --- Noncompliant: Random in security context (CRITICAL) ---

fun generateToken(): String { // Noncompliant
    return java.lang.Long.toHexString(Random().nextLong())
}

fun generateSalt(): ByteArray { // Noncompliant
    val salt = ByteArray(16)
    Random().nextBytes(salt)
    return salt
}

fun generateSessionId(): String { // Noncompliant
    return Math.random().toString()
}

// --- Noncompliant: fixed-seed SecureRandom (CRITICAL, always) ---

fun fixedSeedRandom(): ByteArray { // Noncompliant
    val sr = SecureRandom(byteArrayOf(1, 2, 3))
    val nonce = ByteArray(12)
    sr.nextBytes(nonce)
    return nonce
}

// --- Compliant: no security context (skip) ---

fun rollDice(): Int { // Compliant — game logic
    return Random().nextInt(6) + 1
}

// --- Compliant: proper SecureRandom ---

fun secureNonce(): ByteArray { // Compliant
    val sr = SecureRandom()
    val nonce = ByteArray(12)
    sr.nextBytes(nonce)
    return nonce
}
