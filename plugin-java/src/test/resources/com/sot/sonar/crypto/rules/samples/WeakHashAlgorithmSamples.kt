package samples

import java.security.MessageDigest
import org.apache.commons.codec.digest.DigestUtils
import com.google.common.hash.Hashing
import org.bouncycastle.crypto.digests.MD5Digest
import org.bouncycastle.crypto.digests.SHA1Digest

// --- Noncompliant: security context (CRITICAL) ---

fun hashToken(token: String): ByteArray { // Noncompliant
    val md = MessageDigest.getInstance("MD5")
    return md.digest(token.toByteArray())
}

fun hashPassword(password: String): String { // Noncompliant
    return DigestUtils.md5Hex(password)
}

// --- Noncompliant: neutral context (MAJOR) ---

fun compute(data: ByteArray): ByteArray { // Noncompliant
    return MessageDigest.getInstance("SHA1").digest(data)
}

// BouncyCastle — always noncompliant
fun bouncyCastle() {
    val d1 = MD5Digest() // Noncompliant
    val d2 = SHA1Digest() // Noncompliant
}

// --- Compliant: non-security context (skip) ---

fun computeEtag(body: ByteArray): String { // Compliant — etag context
    return DigestUtils.md5Hex(body)
}

fun buildCacheKey(url: String): String { // Compliant — cache context
    return Hashing.md5().hashString(url, Charsets.UTF_8).toString()
}

// --- Compliant: strong algorithm ---

fun safeHash(data: ByteArray): ByteArray { // Compliant
    return MessageDigest.getInstance("SHA-256").digest(data)
}
