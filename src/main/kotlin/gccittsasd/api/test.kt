import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.cio.*
import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.client.plugins.websocket.webSocket
import io.ktor.client.request.*
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.websocket.Frame
import io.ktor.websocket.readText
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
    val keyRes = HttpClient(CIO).get("http://localhost:8080/key")
    val spec = X509EncodedKeySpec(Base64.getDecoder().decode(keyRes.body<String>()))
    val key = KeyFactory.getInstance("RSA").generatePublic(spec)
    val cipher = Cipher.getInstance("RSA/ECB/OAEPPadding")
    cipher.init(Cipher.ENCRYPT_MODE, key)

    // account creation
//    val create = HttpClient(CIO).post("http://localhost:8080/accounts/create") {
//        setBody("{\"username\": \"admin\", \"password\": \"${Base64.getEncoder().encodeToString(cipher.doFinal("${"password".sha256()}:ID=${SecureRandom().nextFloat().toString().sha256()}".toByteArray()))}\"}")
//    }
//    println(create.status)

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

    // account logout
//    val logout = HttpClient(CIO).post("http://localhost:8080/accounts/logout") {
//        setBody("{\"token\": \"${Base64.getEncoder().encodeToString(cipher.doFinal("$token:ID=${SecureRandom().nextFloat().toString().sha256()}".toByteArray()))}\"}")
//    }
//    println(logout.status)

    // account deletion
//    val identifier = SecureRandom().nextFloat().toString().sha256()
//    val delete = HttpClient(CIO).post("http://localhost:8080/accounts/delete") {
//        setBody("{\"token\": \"${Base64.getEncoder().encodeToString(cipher.doFinal("$token:ID=$identifier".toByteArray()))}\", \"password\":  \"${Base64.getEncoder().encodeToString(cipher.doFinal("${"password".sha256()}:ID=$identifier".toByteArray()))}\"}")
//    }
//    println(delete.status)

    // send in a file
    val identifier = SecureRandom().nextFloat().toString().sha256()
    val fileSent = HttpClient(CIO).post("http://localhost:8080/exchange/forward") {
        setBody("{\"token\": \"${
                Base64.getEncoder().encodeToString(
                    cipher.doFinal(
                        "$token:ID=${identifier}".toByteArray()
                    )
                )
            }\", \"task\": {\"command\": \"run-file\", \"file_name\": \"test.py\", \"file_content\": \"ZnJvbSBGbGlnaHRSYWRhcjI0IGltcG9ydCBGbGlnaHRSYWRhcjI0QVBJDQppbXBvcnQgZGF0ZXRpbWUNCmltcG9ydCByYW5kb20NCmltcG9ydCBvcw0KaW1wb3J0IHRpbWUNCmltcG9ydCB0aHJlYWRpbmcNCg0KZnJvbSBGbGlnaHRSYWRhcjI0LmVycm9ycyBpbXBvcnQgQ2xvdWRmbGFyZUVycm9yDQoNCmZyQVBJID0gRmxpZ2h0UmFkYXIyNEFQSSgpDQpmbGlnaHRzID0gZnJBUEkuZ2V0X2ZsaWdodHMoKQ0KDQptYXhUaW1lID0gaW50KGlucHV0KCJUeXBlIHRoZSBtYXhpbXVtIGZsaWdodCB0aW1lIGluIGhvdXJzID4+PiAiKSkNCm9zLnN5c3RlbSgnY2xzJykNCg0Kd2hpbGUgVHJ1ZToNCiAgICBmbGlnaHQgPSByYW5kb20uY2hvaWNlKGZsaWdodHMpDQogICAgdHJ5Og0KICAgICAgICBmbGlnaHQuc2V0X2ZsaWdodF9kZXRhaWxzKGZyQVBJLmdldF9mbGlnaHRfZGV0YWlscyhmbGlnaHQpKQ0KICAgIGV4Y2VwdCBDbG91ZGZsYXJlRXJyb3I6DQogICAgICAgIHByaW50KCJFUlJPUjogdG9vIG1hbnkgY2FsbHMgbWFkZSwgYXBpIGhhcyBkZW5pZWQgcmVzcG9uc2VzLiBXYWl0aW5nIDUgc2Vjb25kcyBiZWZvcmUgcmV0cnlpbmciKQ0KICAgICAgICB0aW1lLnNsZWVwKDUpDQogICAgICAgIGNvbnRpbnVlDQoNCiAgICB0cnk6DQogICAgICAgIGRlcGFydHVyZSA9IGRhdGV0aW1lLmRhdGV0aW1lLmZyb210aW1lc3RhbXAoZmxpZ2h0LnRpbWVfZGV0YWlsc1snc2NoZWR1bGVkJ11bJ2RlcGFydHVyZSddKQ0KICAgICAgICBhcnJpdmFsID0gZGF0ZXRpbWUuZGF0ZXRpbWUuZnJvbXRpbWVzdGFtcChmbGlnaHQudGltZV9kZXRhaWxzWydzY2hlZHVsZWQnXVsnYXJyaXZhbCddKQ0KICAgIGV4Y2VwdDoNCiAgICAgICAgY29udGludWUNCg0KICAgIGlmIGRlcGFydHVyZS55ZWFyICE9IGRhdGV0aW1lLmRhdGV0aW1lLm5vdygpLnllYXI6DQogICAgICAgIGNvbnRpbnVlDQogICAgaWYgYXJyaXZhbC5ob3VyIC0gZGVwYXJ0dXJlLmhvdXIgPiBtYXhUaW1lIG9yIChhcnJpdmFsLmhvdXIgLSBkZXBhcnR1cmUuaG91cikgKiAtMSA+IG1heFRpbWU6DQogICAgICAgIHByaW50KGYiRmxpZ2h0IGZvdW5kIHdpdGggd3JvbmcgbGVuZ3RoOiB7YXJyaXZhbCAtIGRlcGFydHVyZX0iKQ0KICAgICAgICBjb250aW51ZQ0KDQogICAgcHJpbnQoDQogICAgICAgIGYiQWlyY3JhZnQ6ICAgICB7ZmxpZ2h0LmFpcmNyYWZ0X21vZGVsfVxuQWlybGluZTogICAgICB7ZmxpZ2h0LmFpcmxpbmVfbmFtZX1cbkNhbGxzaWduOiAgICAge2ZsaWdodC5jYWxsc2lnbn1cblJlZ2lzdHJhdGlvbjoge2ZsaWdodC5yZWdpc3RyYXRpb259XG5PcmlnaW46ICAgICAgIHtmbGlnaHQub3JpZ2luX2FpcnBvcnRfaWF0YX0gLSB7ZmxpZ2h0Lm9yaWdpbl9haXJwb3J0X25hbWV9XG5EZXN0aW5hdGlvbjogIHtmbGlnaHQuZGVzdGluYXRpb25fYWlycG9ydF9pYXRhfSAtIHtmbGlnaHQuZGVzdGluYXRpb25fYWlycG9ydF9uYW1lfVxuTGluazogICAgICAgICBodHRwczovL2ZsaWdodHJhZGFyMjQuY29tL3tmbGlnaHQuY2FsbHNpZ259XG5EZXBhcnR1cmU6ICAgIHtkZXBhcnR1cmV9XG5BcnJpdmFsOiAgICAgIHthcnJpdmFsfVxuVG90YWwgVGltZTogICB7YXJyaXZhbCAtIGRlcGFydHVyZX0iDQogICAgKQ0KDQogICAgcXVlcnkgPSBpbnB1dCgnUHJlc3MgZW50ZXIgdG8gZmluZCBhbm90aGVyJykNCiAgICBvcy5zeXN0ZW0oJ2Nscycp\"}}")
    }
    println("${fileSent.status} - ${fileSent.body<String>()}")

    // connect to websocket
    val websocket = HttpClient(CIO) {
        install(WebSockets)
    }.webSocket(
        method = HttpMethod.Get,
        host = "localhost",
        port = 8080,
        path = "/exchange/connect"
    ) {
        while (true) {
            val message = incoming.receive() as? Frame.Text
                ?: continue
            println(message.readText())
            if (message.readText() == "token") {
                send(Frame.Text(Base64.getEncoder().encodeToString(cipher.doFinal("$token:ID=${SecureRandom().nextFloat().toString().sha256()}".toByteArray()))))
            }
        }
    }
}