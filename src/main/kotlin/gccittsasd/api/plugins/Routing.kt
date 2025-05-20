package gccittsasd.api.plugins

// import necessary packages (kotlin uses a lot)
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
import io.ktor.server.websocket.webSocket
import io.ktor.websocket.*
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
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
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.Cipher
import kotlin.time.TimeMark
import kotlin.time.TimeSource

val gpuClients = ConcurrentHashMap<String, WebSocketSession>() // hashmap of token to session
val gpuData = ConcurrentHashMap<String, Float>() // hashmap of token to gpu data (in json)
val gpuResponses = ConcurrentHashMap<String, String>() // hashmap of token to output

// function to sha256 hash anything
fun Any.sha256(): String {
    var input = this
    if (this !is ByteArray) { // if the argument isnt a bytearray, make it one. this is necessary to run the digest function
        input = this.toString().toByteArray()
    }
    return MessageDigest
        .getInstance("SHA-256") // select sha256
        .digest(input)
        .fold("") { str, it -> str + "%02x".format(it) } // add the text in a specific way
}

// api routing
fun Application.configureRouting() {
    val uniqueIdentifications = mutableListOf<String>() // list of used identifications. this prevents piggybacking attacks on the rsa encryption
    val activeIdentifications = mutableMapOf<String, List<Any>>() // list of logged in tokens and what they correspond to

    // initialize rsa by creating a private and public key then making the cipher decryption method
    val generator = KeyPairGenerator.getInstance("RSA")
    generator.initialize(2048, SecureRandom()) // sets keysize to 2048 bits and gives a secure constructor to provide random numbers
    val keyPair = generator.genKeyPair()
    val cipher = Cipher.getInstance("RSA/ECB/OAEPPadding") // set OAEP padding for compatibility with node js encryption
    cipher.init(Cipher.DECRYPT_MODE, keyPair.private)

    routing { // list of routes and functions to handle them
        // return the public rsa key so users can encrypt messages and server can decrypt them
        get("/key") {
            call.respondText(Base64.getEncoder().encodeToString(keyPair.public.encoded), ContentType.parse("text/plain"))
        }

        // call to create a new account in the database
        post("accounts/create") {
            // check if post body has required fields
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

            // decrypt password
            val username = body.string("username")!!
            val plaintext = String(cipher.doFinal(Base64.getDecoder().decode(body.string("password")!!))).split(":ID=")
            val password = plaintext[0]
            val identifier = plaintext[1]

            // check for valid identification
            if (uniqueIdentifications.contains(identifier)) {
                call.respond(HttpStatusCode.Unauthorized)
                return@post
            }

            // check if somebody is already registered with that username
            var unique: Boolean? = null
            runBlocking {
                // make request to database looking for all records with same username
                val res = HttpClient(CIO).get("https://api.airtable.com/v0/app5kgg3I15QSwFhT/Accounts?fields%5B%5D=Username&filterByFormula=%7BUsername%7D+%3D+'${URLEncoder.encode(username, "UTF-8")}'") {
                    headers {
                        bearerAuth(dotenv()["AIRTABLE_API_TOKEN"])
                    }
                }
                val airtableCheckBody = Parser.default().parse(StringBuilder(res.body<String>())) as JsonObject
                unique = airtableCheckBody.array<JsonObject>("records")?.none() // true if there is no records returned
            }
            if (unique == null) { // shouldnt be possible but necessary for kotlin typecasting
                call.respond(HttpStatusCode.InternalServerError)
                return@post
            } else if (!unique) {
                call.respond(HttpStatusCode.Forbidden) // return 403 forbidden if its not a unique username
                return@post
            }

            // create record to append to
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
                // make request to database to add record
                val res = HttpClient(CIO).post("https://api.airtable.com/v0/app5kgg3I15QSwFhT/Accounts") {
                    headers {
                        bearerAuth(dotenv()["AIRTABLE_API_TOKEN"])
                        contentType(ContentType.Application.Json)
                    }
                    setBody(Klaxon().toJsonString(record))
                }
                status = res.status.value
            }
            if (status == 200) call.respond(HttpStatusCode.OK) // if record was added well, return 200 OK
        }

        // call to login to an existing account and receive a token to use in future calls
        post("accounts/login") {
            // check if post body has username, password, and key fields
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

            // decrypt password and generate rsa public key based on key parameter
            val username = body.string("username")!!
            val plaintext = String(cipher.doFinal(Base64.getDecoder().decode(body.string("password")!!))).split(":ID=")
            val password = plaintext[0]
            val identifier = plaintext[1]
            val key = KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(Base64.getDecoder().decode(body.string("key")!!.replace("\r", ""))))

            // check identification
            if (uniqueIdentifications.contains(identifier)) {
                call.respond(HttpStatusCode.Unauthorized)
                return@post
            } else {
                uniqueIdentifications += identifier
            }

            // check if login information is correct
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
            if (correct == null) { // shouldnt be possible but necessary for kotlin typecasting
                call.respond(HttpStatusCode.Forbidden)
                return@post
            } else if (!correct) { // separate if statement instead of || operator to allow typecasting
                call.respond(HttpStatusCode.Forbidden)
                return@post
            }

            // make token from hash of securely random number and current time
            // the token has no pattern at all so you would need to get the exact millisecond this line of code ran and check all floats between 0 and 1
            // nobodys gonna do that, so its not vulnerable to predictable token attacks
            val token = "${SecureRandom().nextFloat()}:${System.currentTimeMillis()}".sha256()
            activeIdentifications += token to listOf(TimeSource.Monotonic.markNow(), username) // time to check time elapsed and have a timeout point

            // return the encrypted token so it cant be intercepted but user can still use it
            val encrypt = Cipher.getInstance("RSA/ECB/OAEPPadding")
            encrypt.init(Cipher.ENCRYPT_MODE, key)
            call.respondText(Base64.getEncoder().encodeToString(encrypt.doFinal(token.toByteArray())))
        }

        // call to logout of an account
        // all thats required is a token because it cant break anything or mess with the user in any way so you can just delete the token from the list
        // this is pretty much automatically run if a call is made over 3 hours from the login
        post("accounts/logout") {
            // check for token parameter
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

            // decrypt token
            // probably unnecessary because it is being deleted anyway but the risk is:
            // an attacker could intercept the request and stop it from going through and use the token themselves for something else
            val plaintext = String(cipher.doFinal(Base64.getDecoder().decode(body.string("token")!!))).split(":ID=")
            val token = plaintext[0]
            val identifier = plaintext[1]

            // check identification, also unnecessary since the request cant be run twice but might as well follow common structure
            if (uniqueIdentifications.contains(identifier)) {
                call.respond(HttpStatusCode.Unauthorized)
                return@post
            } else {
                uniqueIdentifications += identifier
            }

            // remove token from list or return an error if they werent logged in to begin with
            if (token in activeIdentifications) {
                activeIdentifications.remove(token)
                call.respond(HttpStatusCode.OK)
            } else {
                call.respond(HttpStatusCode.ExpectationFailed)
            }
        }

        // delete an account
        post("accounts/delete") {
            // check for a token and password for additional verification
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

            // decrypt both token and password
            val tokenPlaintext = String(cipher.doFinal(Base64.getDecoder().decode(body.string("token")!!))).split(":ID=")
            val passwordPlaintext = String(cipher.doFinal(Base64.getDecoder().decode(body.string("password")!!))).split(":ID=")
            val token = tokenPlaintext[0]
            val password = passwordPlaintext[0]
            val identifier = tokenPlaintext[1]

            // check both identifications, which should also be the same identification but not used before
            if (tokenPlaintext[1] != passwordPlaintext[1] || uniqueIdentifications.contains(identifier) || token !in activeIdentifications) {
                call.respond(HttpStatusCode.Unauthorized)
                return@post
            } else {
                uniqueIdentifications += identifier
            }

            // check if more than 3 hours have elapsed and timeout the user if they have
            val time = (activeIdentifications[token]!![0] as TimeMark).elapsedNow()

            if (time.inWholeHours > 3) {
                activeIdentifications.remove(token)
                call.respond(HttpStatusCode.Unauthorized)
                return@post
            }

            // remove token from logged in users, if its not logged in it will return an error anyway so nothing will be affected...
            val username = activeIdentifications[token]!![1] as String
            activeIdentifications.remove(token)

            // check if password is correct
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
                id = airtableCheckBody.array<JsonObject>("records")?.get(0)?.string("id") // get record id for deletion
            }
            if (correct == null) { // shouldnt be possible, but necessary for kotlin typecasting
                call.respond(HttpStatusCode.Forbidden)
                return@post
            } else if (!correct) {
                call.respond(HttpStatusCode.Forbidden)
                return@post
            }

            // database call to remove account
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

        // send in a file
        post("exchange/forward") {
            // get token and task
            val (token, task) = try {
                val req = call.receiveText()
                // used different ways of parsing json
                val body = Json.parseToJsonElement(req).jsonObject
                val token = body["token"]?.jsonPrimitive?.content
                    ?: return@post call.respond(HttpStatusCode.BadRequest, "Missing token")
                val task = body["task"]?.jsonObject
                    ?: return@post call.respond(HttpStatusCode.BadRequest, "Missing task object")
                token to task
            } catch (e: Exception) {
                return@post call.respond(HttpStatusCode.BadRequest, "Invalid request $e")
            }
            println("obtained token and task")
            println(task)
            // decode and get hash of file
            val decoded = Base64.getDecoder().decode(task.toMap()["file_content"].toString().replace("\"", ""))
            val hash = decoded.sha256()
            // get virus total key from .env variables and check it
            val key = dotenv()["VIRUSTOTAL_API_KEY"]
            if (key.isNullOrEmpty()) {
                throw Exception("Key is empty")
            }
            var passed: Boolean = false // will be used later (line 433)
            runBlocking {
                // check if there is already a report for the file based on the hash
                val client = OkHttpClient()
                val request = Request.Builder()
                    .url("https://www.virustotal.com/api/v3/files/$hash")
                    .get()
                    .addHeader("accept", "application/json")
                    .addHeader("x-apikey", key)
                    .build()
                val response = client.newCall(request).execute()
                val body = response.body()!!.string()
                // check if file is either not found or malicious and respond accordingly
                if ("NotFoundError" !in body && "\"malicious\": 0," !in body) {
                    call.respond(HttpStatusCode.NotAcceptable)
                    println("malicous, blocking")
                    return@runBlocking
                } else if ("NotFoundError" !in body) {
                    passed = true
                    println("previous scan showed no malware, passed")
                    return@runBlocking
                }
                // get a new url for uploading larger files
                val urlRequest = Request.Builder()
                    .url("https://www.virustotal.com/api/v3/files/upload_url")
                    .get()
                    .addHeader("accept", "application/json")
                    .addHeader("x-apikey", key)
                    .build()
                val url = (Parser.default().parse(StringBuilder(client.newCall(urlRequest).execute().body()!!.string())) as JsonObject).string("data")!!
                // get url of the report for the file
                val postBody = MultipartBody.Builder() // create the body as a multipart form
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
                // check the report on the file
                val analysesRequest = Request.Builder() // btw virustotal does actually spell analysis "analyses" for some reason
                    .url(analysesUrl)
                    .get()
                    .addHeader("accept", "application/json")
                    .addHeader("x-apikey", key)
                    .build()
                val analyses = client.newCall(analysesRequest).execute().body()!!.string()
                if ("\"malicious\": 0," !in analyses) { // analyze the analysis
                    call.respond(HttpStatusCode.NotAcceptable)
                    println("scan found malware, blocking")
                    return@runBlocking
                } else {
                    passed = true
                    println("scan found no malware, passed")
                    return@runBlocking
                }
            }
            if (!passed) { // end lambda before adding the file if it didnt pass
                return@post
            }
            // get best available gpu
            val bestGpu = gpuData.entries.maxByOrNull { it.value }
            if (bestGpu == null) { // if there is no gpus
                call.respond(HttpStatusCode.ExpectationFailed, "No GPU's available") // respond with that
                return@post
            }
            println("found bestGpu")
            println(bestGpu)
            val gpuToken = bestGpu.key
            val gpuSession = gpuClients[gpuToken]
            if (gpuSession == null) { // happens if client exits program early
                call.respond(HttpStatusCode.ExpectationFailed, "GPU Client not available")
                return@post
            }
            println("found gpu session")
            println(gpuSession)
            val taskPayload = task.toMutableMap().apply {
                put("token", JsonPrimitive(token))
            }
            val jsonString = Json.encodeToString(taskPayload)
            println(jsonString)
            try {
                gpuSession.send(Frame.Text(jsonString)) // send the task to the runner
            } catch (_: Error) {
                call.respond(HttpStatusCode.ExpectationFailed, "Failed to forward task") // selected runner is actively disconnecting most likely
                return@post
            }
            println("could send data")
            // wait to get response from runner
            val response = withTimeoutOrNull(30000) { // value can and should be changed if running large scale production, but for basic http its fine
                while (true) {
                    println(token)
                    val res = gpuResponses.remove(token)
                    println(res)
                    println(gpuResponses)
                    if (res != null) {
                        return@withTimeoutOrNull res
                    }
                    delay(100)
                }
            }
            println("got a response: ")
            println(response)
            if (response == null) { // if no response was received
                call.respond(HttpStatusCode.ExpectationFailed, "GPU Client did not respond in time")
            } else {
                val responseBody = Json.parseToJsonElement(response.toString()).jsonObject
                println(responseBody)
                call.respondText(response.toString(), ContentType.Application.Json) // give the response back
            }
        }

        // runner connect method
        webSocket("exchange/connect") {
            val session = this // used later
            val message = incoming.receive() as? Frame.Text ?: return@webSocket // initialize connection with runner info
            val body = Json.parseToJsonElement(message.readText()).jsonObject
            val token = body["token"]?.jsonPrimitive?.content ?: return@webSocket
            val gpus = body["memory"]?.jsonPrimitive?.floatOrNull ?: return@webSocket

            gpuClients[token] = session // gives access to internal functions from other request handlers
            gpuData[token] = gpus // stores gpu data
            println(gpuData)
            println(gpuClients)
            while (true) {
                val frame = withTimeoutOrNull(31 * 60 * 1000) {incoming.receive()} ?: break // get frame
                when (frame) { // different handlers for different types of content received
                    is Frame.Text -> {
                        // Parse the incoming frame as a JSON object
                        val frameJson = Json.parseToJsonElement(frame.readText()).jsonObject
                        println(frameJson)
                        val output = frameJson["output"]
                        println(output)

                        if (output != null && output.toString() != "0") { // if there is an output
                            val forwardingToken = frameJson["forwarding_token"]?.jsonPrimitive?.content
                            println(forwardingToken)
                            if (forwardingToken != null) {
                                gpuResponses[forwardingToken.toString()] = output.toString() // add it to responses
                                println("gpu responses:")
                                println(gpuResponses)
                            }
                        } else {
                            val updatedGpus = frameJson["memory"]?.jsonPrimitive?.floatOrNull // gets vram again to update system info
                                ?: break
                            gpuData[token] = updatedGpus
                        }
                    }
                    is Frame.Close -> break // ends script if connection closed
                    else -> Unit // nothing happened this frame
                }
            }
            // remove info after script is done
            gpuClients.remove(token)
            gpuData.remove(token)
            println("Connection closed successfully")
        }
    }
}
