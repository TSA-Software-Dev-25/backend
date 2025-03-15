package gccittsasd.api.plugins

import com.beust.klaxon.JsonObject
import com.beust.klaxon.Klaxon
import com.beust.klaxon.Parser
import io.github.cdimascio.dotenv.dotenv
import io.ktor.client.HttpClient
import io.ktor.client.call.*
import io.ktor.client.engine.cio.CIO
import io.ktor.client.request.bearerAuth
import io.ktor.client.request.delete
import io.ktor.client.request.get
import io.ktor.client.request.parameter
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.coroutines.runBlocking
import okhttp3.MediaType
import okhttp3.MultipartBody
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import java.net.URLEncoder
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import javax.crypto.Cipher
import kotlin.time.TimeMark
import kotlin.time.TimeSource

fun Any.sha256(): String {
    var input = this
    if (this !is ByteArray) {
        input = this.toString().toByteArray()
    }
    return MessageDigest
        .getInstance("SHA-256")
        .digest(input)
        .fold("") { str, it -> str + "%02x".format(it) }
}

fun Application.configureRouting() {
    val uniqueIdentifications = mutableListOf<String>()
    val activeIdentifications = mutableMapOf<String, List<Any>>()

    val generator = KeyPairGenerator.getInstance("RSA")
    generator.initialize(2048, SecureRandom())
    val keyPair = generator.genKeyPair()
    val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
    cipher.init(Cipher.DECRYPT_MODE, keyPair.private)

    val activelySending = mutableListOf<String>()

    routing {
        get("/key") {
            call.respondText(Base64.getEncoder().encodeToString(keyPair.public.encoded), ContentType.parse("text/plain"))
        }

        post("accounts/create") {
            val body: JsonObject
            try {
                val req = call.receive<String>()
                println(req)
                body = Parser.default().parse(StringBuilder(req)) as JsonObject
                body.string("username")!!
                body.string("password")!!
            } catch (_: Error) {
                call.respond(HttpStatusCode.BadRequest)
                return@post
            }

            val username = body.string("username")!!
            val plaintext = String(cipher.doFinal(Base64.getDecoder().decode(body.string("password")!!))).split(":ID=")
            val password = plaintext[0]
            val identifier = plaintext[1]

            if (uniqueIdentifications.contains(identifier)) {
                call.respond(HttpStatusCode.Unauthorized)
                return@post
            } else {
                uniqueIdentifications += identifier
            }

            var unique: Boolean? = null
            runBlocking {
                val res = HttpClient(CIO).get("https://api.airtable.com/v0/app5kgg3I15QSwFhT/Accounts?fields%5B%5D=Username&filterByFormula=%7BUsername%7D+%3D+'${URLEncoder.encode(username, "UTF-8")}'") {
                    headers {
                        bearerAuth(dotenv()["AIRTABLE_API_TOKEN"])
                    }
                }
                val airtableCheckBody = Parser.default().parse(StringBuilder(res.body<String>())) as JsonObject
                unique = airtableCheckBody.array<JsonObject>("records")?.none()
            }
            if (unique == null) {
                call.respond(HttpStatusCode.InternalServerError)
                return@post
            } else if (!unique) {
                call.respond(HttpStatusCode.Forbidden)
                return@post
            }

            val record = mapOf(
                "records" to listOf(
                    mapOf(
                        "fields" to mapOf(
                            "Username" to username,
                            "Password" to password
                        )
                    )
                )
            )

            val status: Int
            runBlocking {
                val res = HttpClient(CIO).post("https://api.airtable.com/v0/app5kgg3I15QSwFhT/Accounts") {
                    headers {
                        bearerAuth(dotenv()["AIRTABLE_API_TOKEN"])
                        contentType(ContentType.Application.Json)
                    }
                    setBody(Klaxon().toJsonString(record))
                }
                status = res.status.value
            }
            if (status == 200) call.respond(HttpStatusCode.OK)
        }

        post("accounts/login") {
            val body: JsonObject
            try {
                val req = call.receive<String>()
                println(req)
                body = Parser.default().parse(StringBuilder(req)) as JsonObject
                body.string("username")!!
                body.string("password")!!
                body.string("key")!!
            } catch (_: Error) {
                call.respond(HttpStatusCode.BadRequest)
                return@post
            }

            val username = body.string("username")!!
            val plaintext = String(cipher.doFinal(Base64.getDecoder().decode(body.string("password")!!))).split(":ID=")
            val password = plaintext[0]
            val identifier = plaintext[1]
            val key = KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(Base64.getDecoder().decode(body.string("key")!!)))

            if (uniqueIdentifications.contains(identifier)) {
                call.respond(HttpStatusCode.Unauthorized)
                return@post
            } else {
                uniqueIdentifications += identifier
            }

            var correct: Boolean? = null
            runBlocking {
                val res = HttpClient(CIO).get("https://api.airtable.com/v0/app5kgg3I15QSwFhT/Accounts?fields=Username&fields=Password&filterByFormula=%7BUsername%7D+%3D+'${URLEncoder.encode(username, "UTF-8")}'") {
                    headers {
                        bearerAuth(dotenv()["AIRTABLE_API_TOKEN"])
                    }
                }
                val airtableCheckBody = Parser.default().parse(StringBuilder(res.body<String>())) as JsonObject
                correct = airtableCheckBody.array<JsonObject>("records")?.get(0)?.obj("fields")?.string("Password") == password
            }
            if (correct == null) {
                call.respond(HttpStatusCode.Forbidden)
                return@post
            } else if (!correct) {
                call.respond(HttpStatusCode.Forbidden)
                return@post
            }

            val token = "${SecureRandom().nextFloat()}:${System.currentTimeMillis()}".sha256()
            activeIdentifications += token to listOf(TimeSource.Monotonic.markNow(), username)

            val encrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding")
            encrypt.init(Cipher.ENCRYPT_MODE, key)
            call.respondText(Base64.getEncoder().encodeToString(encrypt.doFinal(token.toByteArray())))
        }

        post("accounts/logout") {
            val body: JsonObject
            try {
                val req = call.receive<String>()
                println(req)
                body = Parser.default().parse(StringBuilder(req)) as JsonObject
                body.string("token")!!
            } catch (_: Error) {
                call.respond(HttpStatusCode.BadRequest)
                return@post
            }

            val plaintext = String(cipher.doFinal(Base64.getDecoder().decode(body.string("token")!!))).split(":ID=")
            val token = plaintext[0]
            val identifier = plaintext[1]

            if (uniqueIdentifications.contains(identifier)) {
                call.respond(HttpStatusCode.Unauthorized)
                return@post
            } else {
                uniqueIdentifications += identifier
            }

            if (token in activeIdentifications) {
                activeIdentifications.remove(token)
                call.respond(HttpStatusCode.OK)
            } else {
                call.respond(HttpStatusCode.ExpectationFailed)
            }
        }

        post("accounts/delete") {
            val body: JsonObject
            try {
                val req = call.receive<String>()
                println(req)
                body = Parser.default().parse(StringBuilder(req)) as JsonObject
                body.string("token")!!
                body.string("password")!!
            } catch (_: Error) {
                call.respond(HttpStatusCode.BadRequest)
                return@post
            }

            val tokenPlaintext = String(cipher.doFinal(Base64.getDecoder().decode(body.string("token")!!))).split(":ID=")
            val passwordPlaintext = String(cipher.doFinal(Base64.getDecoder().decode(body.string("password")!!))).split(":ID=")
            val token = tokenPlaintext[0]
            val password = passwordPlaintext[0]
            val identifier = tokenPlaintext[1]

            if (tokenPlaintext[1] != passwordPlaintext[1] || uniqueIdentifications.contains(identifier) || token !in activeIdentifications) {
                call.respond(HttpStatusCode.Unauthorized)
                return@post
            } else {
                uniqueIdentifications += identifier
            }

            val time = (activeIdentifications[token]!![0] as TimeMark).elapsedNow()

            if (time.inWholeHours > 3) {
                activeIdentifications.remove(token)
                call.respond(HttpStatusCode.Unauthorized)
                return@post
            }

            val username = activeIdentifications[token]!![1] as String
            activeIdentifications.remove(token)

            var correct: Boolean? = null
            val id: String?
            runBlocking {
                val res = HttpClient(CIO).get("https://api.airtable.com/v0/app5kgg3I15QSwFhT/Accounts?fields=Username&fields=Password&filterByFormula=%7BUsername%7D+%3D+'${URLEncoder.encode(username, "UTF-8")}'") {
                    headers {
                        bearerAuth(dotenv()["AIRTABLE_API_TOKEN"])
                    }
                }
                val airtableCheckBody = Parser.default().parse(StringBuilder(res.body<String>())) as JsonObject
                correct = airtableCheckBody.array<JsonObject>("records")?.get(0)?.obj("fields")?.string("Password") == password
                id = airtableCheckBody.array<JsonObject>("records")?.get(0)?.string("id")
            }
            if (correct == null) {
                call.respond(HttpStatusCode.Forbidden)
                return@post
            } else if (!correct) {
                call.respond(HttpStatusCode.Forbidden)
                return@post
            }

            runBlocking {
                val res = HttpClient(CIO).delete("https://api.airtable.com/v0/app5kgg3I15QSwFhT/Accounts") {
                    headers {
                        bearerAuth(dotenv()["AIRTABLE_API_TOKEN"])
                    }
                    parameter("records[]", id)
                }
                call.respond(HttpStatusCode.fromValue(res.status.value))
            }
        }

        post("exchange/send") {
            val body: JsonObject
            try {
                val req = call.receive<String>()
                println(req)
                body = Parser.default().parse(StringBuilder(req)) as JsonObject
                body.string("token")!!
                body.string("file")!!
            } catch (_: Error) {
                call.respond(HttpStatusCode.BadRequest)
                return@post
            }

            val tokenPlaintext = String(cipher.doFinal(Base64.getDecoder().decode(body.string("token")!!))).split(":ID=")
            val identifier = tokenPlaintext[1]
            val token = tokenPlaintext[0]
            val file = body.string("file")!!

            if (uniqueIdentifications.contains(identifier) || token !in activeIdentifications) {
                call.respond(HttpStatusCode.Unauthorized)
                return@post
            } else {
                uniqueIdentifications += identifier
            }

            val time = (activeIdentifications[token]!![0] as TimeMark).elapsedNow()

            if (time.inWholeHours > 3) {
                activeIdentifications.remove(token)
                call.respond(HttpStatusCode.Unauthorized)
                return@post
            }

            val decoded = Base64.getDecoder().decode(file)
            val hash = decoded.sha256()

            val key = dotenv()["VIRUSTOTAL_API_KEY"]
            if (key.isNullOrEmpty()) {
                throw Exception("Key is empty")
            }
            var passed: Boolean = false
            runBlocking {
                val client = OkHttpClient()
                val request = Request.Builder()
                    .url("https://www.virustotal.com/api/v3/files/$hash")
                    .get()
                    .addHeader("accept", "application/json")
                    .addHeader("x-apikey", key)
                    .build()
                val response = client.newCall(request).execute()
                val body = response.body()!!.string()
                if ("NotFoundError" !in body && "\"malicious\": 0," !in body) {
                    call.respond(HttpStatusCode.NotAcceptable)
                    return@runBlocking
                } else if ("NotFoundError" !in body) {
                    passed = true
                    return@runBlocking
                }
                val urlRequest = Request.Builder()
                    .url("https://www.virustotal.com/api/v3/files/upload_url")
                    .get()
                    .addHeader("accept", "application/json")
                    .addHeader("x-apikey", key)
                    .build()
                val url = (Parser.default().parse(StringBuilder(client.newCall(urlRequest).execute().body()!!.string())) as JsonObject).string("data")!!
                val postBody = MultipartBody.Builder()
                    .setType(MultipartBody.FORM)
                    .addFormDataPart("file", "unknown", RequestBody.create(MediaType.parse("*/*"), decoded))
                    .build()
                val postRequest = Request.Builder()
                    .url(url)
                    .post(postBody)
                    .addHeader("accept", "application/json")
                    .addHeader("content-type", "multipart/form-data")
                    .addHeader("x-apikey", key)
                    .build()
                val analysesUrl = (Parser.default().parse(StringBuilder(client.newCall(postRequest).execute().body()!!.string())) as JsonObject).obj("data")!!.obj("links")!!.string("self")!!
                val analysesRequest = Request.Builder()
                    .url(analysesUrl)
                    .get()
                    .addHeader("accept", "application/json")
                    .addHeader("x-apikey", key)
                    .build()
                val analyses = client.newCall(analysesRequest).execute().body()!!.string()
                if ("\"malicious\": 0," !in analyses) {
                    call.respond(HttpStatusCode.NotAcceptable)
                    return@runBlocking
                } else {
                    passed = true
                    return@runBlocking
                }
            }
            if (!passed) {
                return@post
            }
            activelySending += file
            call.respond(HttpStatusCode.OK)
        }
    }
}