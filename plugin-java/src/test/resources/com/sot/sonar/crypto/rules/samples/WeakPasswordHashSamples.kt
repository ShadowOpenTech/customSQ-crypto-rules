package samples

import java.security.MessageDigest
import java.security.spec.PBEKeySpec
import org.apache.commons.codec.digest.DigestUtils

// --- Noncompliant: Sub-pattern A — general hash on password variable ---

fun storePassword(password: String): ByteArray { // Noncompliant
    return MessageDigest.getInstance("SHA-256").digest(password.toByteArray())
}

fun hashPasswd(passwd: String): String { // Noncompliant
    return DigestUtils.sha1Hex(passwd)
}

fun hashCredentials(credentials: ByteArray): ByteArray { // Noncompliant
    return MessageDigest.getInstance("SHA-512").digest(credentials)
}

// --- Noncompliant: Sub-pattern B — PBKDF2 with low iteration count ---

fun deriveKey(password: CharArray, salt: ByteArray): PBEKeySpec { // Noncompliant — < 600,000
    return PBEKeySpec(password, salt, 10_000, 256)
}

// --- Noncompliant: Sub-pattern C — unsalted hash on password ---

fun unsaltedHash(password: String): ByteArray { // Noncompliant — no salt
    return MessageDigest.getInstance("SHA-256").digest(password.toByteArray())
}

// --- Compliant ---

fun goodDerive(password: CharArray, salt: ByteArray): PBEKeySpec { // Compliant
    return PBEKeySpec(password, salt, 600_000, 256)
}

fun hashFilename(filename: String): ByteArray { // Compliant — not a password
    return MessageDigest.getInstance("SHA-256").digest(filename.toByteArray())
}
