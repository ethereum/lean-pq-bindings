plugins {
    `java-library`
}

group = "org.ethereum"
version = "0.1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(25)
    }
    modularity.inferModulePath = true
}

dependencies {
    testImplementation(platform("org.junit:junit-bom:5.12.2"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

val nativeLibraryName = when {
    System.getProperty("os.name").startsWith("Mac") -> "liblean_pq_native.dylib"
    System.getProperty("os.name").startsWith("Windows") -> "lean_pq_native.dll"
    else -> "liblean_pq_native.so"
}
val nativeLibrary = rootProject.projectDir.resolve("../../target/release/$nativeLibraryName")

val buildNative by tasks.registering(Exec::class) {
    commandLine("cargo", "build", "--manifest-path", "../native/Cargo.toml", "--release")
}

tasks.test {
    dependsOn(buildNative)
    useJUnitPlatform()
    systemProperty("lean.pq.native.path", nativeLibrary.absolutePath)
    // Gradle executes JUnit tests on the class path. Published consumers use the narrower named
    // module permission documented in README.md.
    jvmArgs("--enable-native-access=ALL-UNNAMED")
}
