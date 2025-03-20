plugins {
    kotlin("jvm") version "2.0.20"
    id("io.ktor.plugin") version "3.0.0"
}

group = "gccittsasd.api"
version = "0.0.0"

sourceSets {
    main {
        kotlin {
            srcDir("src/main/kotlin")
        }
        resources {
            srcDir("src/main/resources")
        }
    }
}

application {
    mainClass.set("io.ktor.server.netty.EngineMain")
    applicationDefaultJvmArgs = listOf("-Dio.ktor.development=false")
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("io.ktor:ktor-server-content-negotiation")
    implementation("io.ktor:ktor-server-core-jvm")
    implementation("io.ktor:ktor-serialization-kotlinx-json")
    implementation("io.ktor:ktor-server-netty-jvm")
    implementation("ch.qos.logback:logback-classic:1.4.14")
    implementation("io.ktor:ktor-server-config-yaml")
    testImplementation("io.ktor:ktor-server-test-host-jvm")
    testImplementation("org.jetbrains.kotlin:kotlin-test-junit:2.0.21")
    implementation("io.ktor:ktor-client-logging")
    implementation("io.ktor:ktor-server-websockets")
    implementation("io.ktor:ktor-client-websockets")

    implementation("com.squareup.okhttp3:okhttp:3.10.0")

    implementation("com.beust:klaxon:5.5")
    implementation("io.ktor:ktor-client-core:2.3.12")
    implementation("io.ktor:ktor-client-cio:2.3.12")

    implementation("io.github.cdimascio:dotenv-kotlin:6.3.1")
}

tasks.withType<Copy> {
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
}