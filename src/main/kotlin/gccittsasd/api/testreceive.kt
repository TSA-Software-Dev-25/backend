import io.github.cdimascio.dotenv.dotenv
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.cio.*
import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.client.plugins.websocket.webSocket
import io.ktor.client.request.*
import io.ktor.http.HttpMethod
import io.ktor.websocket.Frame
import io.ktor.websocket.readText
import kotlinx.coroutines.Job
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import javax.crypto.Cipher

suspend fun main() {
    val keyRes = HttpClient(CIO).get("http://localhost:8080/key")
    val spec = X509EncodedKeySpec(Base64.getDecoder().decode(keyRes.body<String>()))
    val key = KeyFactory.getInstance("RSA").generatePublic(spec)
    val cipher = Cipher.getInstance("RSA/ECB/OAEPPadding")
    cipher.init(Cipher.ENCRYPT_MODE, key)

    // account login
    val generator = KeyPairGenerator.getInstance("RSA")
    generator.initialize(2048, SecureRandom())
    val keyPair = generator.genKeyPair()
    val decrypt = Cipher.getInstance("RSA/ECB/OAEPPadding")
    decrypt.init(Cipher.DECRYPT_MODE, keyPair.private)

    val login = HttpClient(CIO).post("http://localhost:8080/accounts/login") {
        setBody("{\"username\": \"admin\", \"password\": \"${Base64.getEncoder().encodeToString(cipher.doFinal("${"password".sha256()}:ID=${SecureRandom().nextFloat().toString().sha256()}".toByteArray()))}\", \"key\": \"${Base64.getEncoder().encodeToString(keyPair.public.encoded)}\"}")
    }

    var token: String? = null
    if (login.status.value == 200) token = String(decrypt.doFinal(Base64.getDecoder().decode(login.body<String>())))
    println(token)
    token ?: throw Exception("token not found")

    // receive a file
    val receive = HttpClient(CIO).post("http://localhost:8080/exchange/connect") {
        setBody("{\"token\": \"${Base64.getEncoder().encodeToString(cipher.doFinal("$token:ID=${SecureRandom().nextFloat().toString().sha256()}".toByteArray()))}\", \"load\": 10, \"memory\": 8000000000}")
    }
    println(receive.status)
    println(receive.body<String>())

    // send output of a file
    val finish = HttpClient(CIO).post("http://localhost:8080/exchange/finish") {
        setBody("{\"token\": \"${Base64.getEncoder().encodeToString(cipher.doFinal("$token:ID=${SecureRandom().nextFloat().toString().sha256()}".toByteArray()))}\", \"output\": \"lorem ipsum or whatever\"}")
    }
}