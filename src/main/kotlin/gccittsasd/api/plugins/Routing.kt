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
import io.ktor.websocket.CloseReason
import io.ktor.websocket.Frame
import io.ktor.websocket.close
import io.ktor.websocket.readText
import kotlinx.coroutines.channels.consumeEach
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
    generator.initialize(2048, SecureRandom())
    val keyPair = generator.genKeyPair()
    val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
    cipher.init(Cipher.DECRYPT_MODE, keyPair.private)

    // keep lists of active files that are either ready to be or currently being received
    val activelySending = mutableMapOf<String, Pair<String, (() -> Unit)?>>()
    val activelyReceiving = mutableMapOf<String, Pair<((String) -> Unit)?, String>>()
    val nextFunction = mutableMapOf<String, ((String) -> Unit)?>() // simpler way of keeping track of the function for activelyReceiving before it comes into use

    routing { // list of routes and functions to handle them
        // return the public rsa key so users can encrypt messages and server can decrypt them
        get("/key") {
            call.respondText(Base64.getEncoder().encodeToString(keyPair.public.encoded), ContentType.parse("text/plain"))
        }

        // call to create a new account in the database
        post("accounts/create") {
            // check if post body has username and password fields
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
            } else {
                uniqueIdentifications += identifier
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
            val key = KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(Base64.getDecoder().decode(body.string("key")!!)))

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
            val encrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding")
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

        // call to send in a file for somebody else to download and use
        post("exchange/send") {
            // check for token and file parameters
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

            // decrypt token and get file
            val tokenPlaintext = String(cipher.doFinal(Base64.getDecoder().decode(body.string("token")!!))).split(":ID=")
            val identifier = tokenPlaintext[1]
            val token = tokenPlaintext[0]
            val file = body.string("file")!!

            // check identification
            if (uniqueIdentifications.contains(identifier) || token !in activeIdentifications) {
                call.respond(HttpStatusCode.Unauthorized)
                return@post
            } else {
                uniqueIdentifications += identifier
            }

            // test token timeout
            val time = (activeIdentifications[token]!![0] as TimeMark).elapsedNow()

            if (time.inWholeHours > 3) {
                activeIdentifications.remove(token)
                call.respond(HttpStatusCode.Unauthorized)
                return@post
            }

            // decode and get hash of file
            val decoded = Base64.getDecoder().decode(file)
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
                    return@runBlocking
                } else if ("NotFoundError" !in body) {
                    passed = true
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
                    return@runBlocking
                } else {
                    passed = true
                    return@runBlocking
                }
            }
            if (!passed) { // end lambda before adding the file if it didnt pass
                return@post
            }
            activelySending += token to (file to null) // add file to list of unreceived files. null is where the update function will go after checking with websocket
            call.respond(HttpStatusCode.OK)
        }

        // call to receive a file for running and returning output
        post("exchange/receive") {
            // check for token, load, and memory parameters
            val body: JsonObject
            try {
                val req = call.receive<String>()
                println(req)
                body = Parser.default().parse(StringBuilder(req)) as JsonObject
                body.string("token")!!
                body.int("load")!! // current load of the system used for deciding on a file
                body.int("memory")!! // current open ram for deciding on a file
            } catch (_: Error) {
                call.respond(HttpStatusCode.BadRequest)
                return@post
            }

            // decrypt token and get load and memory
            val tokenPlaintext = String(cipher.doFinal(Base64.getDecoder().decode(body.string("token")!!))).split(":ID=")
            val identifier = tokenPlaintext[1]
            val token = tokenPlaintext[0]
            val load = body.int("load")!!
            val memory = body.int("memory")!!

            // check identification
            if (uniqueIdentifications.contains(identifier) || token !in activeIdentifications) {
                call.respond(HttpStatusCode.Unauthorized)
                return@post
            } else {
                uniqueIdentifications += identifier
            }

            // check login timeout
            val time = (activeIdentifications[token]!![0] as TimeMark).elapsedNow()

            if (time.inWholeHours > 3) {
                activeIdentifications.remove(token)
                call.respond(HttpStatusCode.Unauthorized)
                return@post
            }

            // returns no content if there is no file to serve
            if (activelySending.isEmpty()) {
                call.respond(HttpStatusCode.NoContent)
            }

            val choice = activelySending.keys.random() // get random file key (equals a token, but is used to get values)
            // TODO: make it not random...
            if (nextFunction[choice] != null) { // if there is a websocket set up
                activelySending[choice]!!.second!!.invoke() // run the websockets function to update sender
                activelyReceiving += choice to (nextFunction[choice]!! to token) // and setup the next function
            } else {
                activelyReceiving += choice to (null to token) // or if its not just leave it null, the sender will pick it up eventually
            }
            call.respondText(activelySending[choice]!!.first, ContentType.parse("application/x-python-code")) // send file as python code
            activelySending -= choice // remove file from the list to avoid multiple people getting the same file
        }

        // call to finish and give output back to sender
        post("exchange/finish") {
            // check for token and output parameters
            val body: JsonObject
            try {
                val req = call.receive<String>()
                println(req)
                body = Parser.default().parse(StringBuilder(req)) as JsonObject
                body.string("token")!!
                body.string("output")!!
            } catch (_: Error) {
                call.respond(HttpStatusCode.BadRequest)
                return@post
            }

            // decrypt token and get output parameter
            val tokenPlaintext = String(cipher.doFinal(Base64.getDecoder().decode(body.string("token")!!))).split(":ID=")
            val identifier = tokenPlaintext[1]
            val token = tokenPlaintext[0]
            val output = body.string("output")!!

            // check identification
            if (uniqueIdentifications.contains(identifier) || token !in activeIdentifications) {
                call.respond(HttpStatusCode.Unauthorized)
                return@post
            } else {
                uniqueIdentifications += identifier
            }

            // no need to validate token since it already was before, also receiver might have logged out at this point

            // check each active file for if it was the one the same caller received
            for (i in activelyReceiving) {
                if (i.value.second == token) {
                    i.value.first?.invoke(output) // invoke function with output parameter
                    // if it doesnt exist because the webhook isnt added yet, the i.value.first will be null and the ?. operator just returns null so the function doesnt run and avoids errors
                }
            }
        }

        // websocket connection to monitor sent file
        webSocket("/output") {
            send(Frame.Text("token")) // confirm connection by sending "token" to the listener
            incoming.consumeEach { frame -> // for each incoming packet
                frame as? Frame.Text ?: return@consumeEach // continue if its not a text frame
                val plain = String(cipher.doFinal(Base64.getDecoder().decode(frame.readText()))).split(":ID=") // decrypt token
                val text = plain[0]
                val ident = plain[1]
                // check identification
                if (uniqueIdentifications.contains(ident)) {
                    call.respond(HttpStatusCode.Unauthorized)
                    return@consumeEach
                } else {
                    uniqueIdentifications += ident
                }
                // handle the token based on the file
                if (text in activelySending) { // if the file is waiting for a receiver
                    send(Frame.Text("Waiting for receiver")) // let the listener know its waiting to be received
                    // add the response lambda to the file in the waiting list
                    activelySending[text] = activelySending[text]!!.first to {
                        runBlocking {
                            send(Frame.Text("Waiting for execution to finish"))
                        }
                    }
                    // add the following lambda to the nextFunction list to prepare for when somebody receives it
                    nextFunction[text] = { result ->
                        runBlocking {
                            send(Frame.Text(result))
                            close(CloseReason(CloseReason.Codes.NORMAL, "Process finished"))
                        }
                    }
                } else if (text in activelyReceiving) { // if the file has been received
                    send(Frame.Text("Waiting for execution to finish")) // let the listener know its received and waiting for output
                    // add the output lambda to the file in the received list
                    activelyReceiving[text] = { result: String ->
                        runBlocking {
                            send(Frame.Text(result))
                            close(CloseReason(CloseReason.Codes.NORMAL, "Process finished"))
                        }
                    } to activelyReceiving[text]!!.second
                } else { // if it cant find the token in any of the files
                    close(CloseReason(CloseReason.Codes.CANNOT_ACCEPT, "Token not found"))
                }
            }
        }
    }
}