import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.cio.*
import io.ktor.client.request.*
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import javax.crypto.Cipher

fun String.sha256(): String {
    return hashString(this, "SHA-256")
}

private fun hashString(input: String, algorithm: String): String {
    return MessageDigest
        .getInstance(algorithm)
        .digest(input.toByteArray())
        .fold("") { str, it -> str + "%02x".format(it) }
}

suspend fun main() {
    // account creation
    val keyRes = HttpClient(CIO).get("http://localhost:8080/key")
    val spec = X509EncodedKeySpec(Base64.getDecoder().decode(keyRes.body<String>()))
    val key = KeyFactory.getInstance("RSA").generatePublic(spec)
    val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
    cipher.init(Cipher.ENCRYPT_MODE, key)

    val create = HttpClient(CIO).post("http://localhost:8080/accounts/create") {
        setBody("{\"username\": \"admin\", \"password\": \"${Base64.getEncoder().encodeToString(cipher.doFinal("${"password".sha256()}:ID=${SecureRandom().nextFloat().toString().sha256()}".toByteArray()))}\"}")
    }
    println(create.status)

    // account login
    val generator = KeyPairGenerator.getInstance("RSA")
    generator.initialize(2048, SecureRandom())
    val keyPair = generator.genKeyPair()
    val decrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding")
    decrypt.init(Cipher.DECRYPT_MODE, keyPair.private)

    val login = HttpClient(CIO).post("http://localhost:8080/accounts/login") {
        setBody("{\"username\": \"admin\", \"password\": \"${Base64.getEncoder().encodeToString(cipher.doFinal("${"password".sha256()}:ID=${SecureRandom().nextFloat().toString().sha256()}".toByteArray()))}\", \"key\": \"${Base64.getEncoder().encodeToString(keyPair.public.encoded)}\"}")
    }

    var token: String? = null
    if (login.status.value == 200) token = String(decrypt.doFinal(Base64.getDecoder().decode(login.body<String>())))
    println(token)

    // account logout
//    val logout = HttpClient(CIO).post("http://localhost:8080/accounts/logout") {
//        setBody("{\"token\": \"${Base64.getEncoder().encodeToString(cipher.doFinal("$token:ID=${SecureRandom().nextFloat().toString().sha256()}".toByteArray()))}\"}")
//    }
//    println(logout.status)

    // account deletion
    val identifier = SecureRandom().nextFloat().toString().sha256()
    val delete = HttpClient(CIO).post("http://localhost:8080/accounts/delete") {
        setBody("{\"token\": \"${Base64.getEncoder().encodeToString(cipher.doFinal("$token:ID=$identifier".toByteArray()))}\", \"password\":  \"${Base64.getEncoder().encodeToString(cipher.doFinal("${"password".sha256()}:ID=$identifier".toByteArray()))}\"}")
    }
    println(delete.status)
}