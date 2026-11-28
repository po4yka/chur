// The Android host application.
//
// `docs/ARCHITECTURE.md` §9 keeps feature modules free of platform key
// implementations and FFI symbols: features depend on interfaces, and only the
// composition root binds them. This module is that composition root and holds
// nothing else — no screen, no vault logic, and no encoder.
//
// It packages `libchur_jni` for every ABI. The library is built by Cargo
// (ADR-0040), not by CMake, so the packaging is a copy into `jniLibs` rather
// than an `externalNativeBuild`.

plugins {
    // AGP 9 carries Kotlin support itself; the kotlin-android plugin is no
    // longer applied and applying it is an error.
    alias(libs.plugins.android.application)
    alias(libs.plugins.compose.compiler)
    alias(libs.plugins.compose.multiplatform)
}

/** The only Android ABIs the Rust adapter is built for and the APK may ship. */
val androidAbis =
    mapOf(
        "arm64-v8a" to "aarch64-linux-android",
        "x86_64" to "x86_64-linux-android",
    )

val releaseVaultTest = providers.gradleProperty("churReleaseVaultTest").orNull == "true"
if (releaseVaultTest) layout.buildDirectory.set(layout.projectDirectory.dir("build/release-vault-test"))

android {
    namespace = "dev.po4yka.chur.android"
    compileSdk =
        libs.versions.androidCompileSdk
            .get()
            .toInt()
    // The pinned NDK of the version catalog: AGP uses it for its own tasks
    // and installs it when it is missing, and the native build script below
    // resolves the same version, so no machine picks a newest installed one.
    ndkVersion = libs.versions.ndk.get()

    defaultConfig {
        applicationId = "dev.po4yka.chur"
        minSdk =
            libs.versions.androidMinSdk
                .get()
                .toInt()
        targetSdk =
            libs.versions.androidTargetSdk
                .get()
                .toInt()
        versionCode = 1
        versionName = "0.1.0"
        testInstrumentationRunner = if (releaseVaultTest) {
            "dev.po4yka.chur.android.ClassicalVaultReleaseTest"
        } else {
            "androidx.test.runner.AndroidJUnitRunner"
        }
        ndk.abiFilters += androidAbis.keys
    }

    buildFeatures {
        compose = true
    }

    if (releaseVaultTest) {
        testBuildType = "release"
        sourceSets.getByName("androidTest").apply {
            setRoot("src/releaseVaultTest")
            assets.srcDir(rootProject.file("test-vectors/compatibility/classical-vault"))
        }
        testOptions.managedDevices.localDevices.create("classicalVaultApi35") {
            device = "Pixel 6"
            sdkVersion = 35
            systemImageSource = "google"
            require64Bit = true
        }
    } else {
        sourceSets.getByName("androidTest").assets.srcDir(rootProject.file("tests/media"))
    }

    signingConfigs {
        create("release") {
            // CI supplies a temporary file; local builds can point at the
            // keystore kept outside the repository. A missing file makes
            // assembleRelease fail instead of producing an unsigned APK.
            storeFile = file(System.getenv("CHUR_RELEASE_KEYSTORE") ?: "missing-release-keystore.p12")
            storePassword = System.getenv("CHUR_RELEASE_PASSWORD") ?: ""
            keyAlias = "chur-release"
            keyPassword = storePassword
        }
    }

    buildTypes {
        getByName("release") {
            isMinifyEnabled = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
            ndk.debugSymbolLevel = "FULL"
            signingConfig = signingConfigs.getByName("release")
        }
    }
}

dependencies {
    implementation(project(":shared:app"))
    implementation(project(":shared:core-vault"))
    implementation(project(":shared:core-platform-keys"))
    implementation(project(":shared:core-sync"))
    implementation(project(":shared:feature-import"))
    implementation(project(":shared:feature-notes"))
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.camera.camera2)
    implementation(libs.androidx.camera.lifecycle)
    implementation(libs.androidx.camera.view)
    implementation(libs.androidx.camera.video)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    // The background schedule of `SYNC_PROTOCOL_V1.md` §7: the worker pulls
    // and stages while locked, and the next unlock applies what it staged.
    // The system security patch line of `ANDROID.md` §25.1, ADR-0059.
    implementation(libs.androidx.security.state)
    implementation(libs.compose.runtime)
    implementation(libs.compose.foundation)
    implementation(libs.compose.material3)
    implementation(libs.compose.ui)
    implementation(libs.kotlinx.coroutines.core)
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.junit)
    androidTestImplementation(libs.androidx.media3.exoplayer)
    androidTestImplementation(libs.androidx.media3.ui)
}

// ---------------------------------------------------------------------------
// The native libraries
// ---------------------------------------------------------------------------

val rustDirectory = rootProject.layout.projectDirectory.dir("rust")
val cargoTargetDirectory = rustDirectory.dir("target")

/**
 * Builds `libchur_jni` for every Android ABI.
 *
 * It shells out to the script rather than to Cargo directly, because the script
 * is where the NDK discovery, the linker variables, the `PATH` the vendored
 * OpenSSL needs, and the symbol check already live; duplicating them here would
 * mean two places to fix when an NDK layout changes.
 */
val cargoBuildAndroid =
    tasks.register<Exec>("cargoBuildAndroid") {
        group = "build"
        description = "Builds libchur_jni for every Android ABI"
        workingDir = rootProject.layout.projectDirectory.asFile
        commandLine("scripts/build-native-targets.sh", "android")
        environment("CARGO_TARGET_DIR", cargoTargetDirectory.asFile.absolutePath)
        // The pinned NDK of the version catalog: the script prefers exactly
        // this one over the newest installed, so the cross-compilation does
        // not change with the machine that runs it.
        environment("CHUR_NDK_VERSION", libs.versions.ndk.get())
        inputs.dir(rustDirectory.dir("crates"))
        inputs.file(rustDirectory.file("Cargo.toml"))
        inputs.file(rustDirectory.file("Cargo.lock"))
        inputs.file(rustDirectory.file("rust-toolchain.toml"))
        inputs.file(rootProject.layout.projectDirectory.file("scripts/build-native-targets.sh"))
        androidAbis.values.forEach { triple ->
            outputs.file(cargoTargetDirectory.file("$triple/release/libchur_jni.so"))
        }
    }

/**
 * Stages the built libraries into the layout the packager expects.
 *
 * AGP 9 refuses a `Provider` in the source-set API, because it cannot tell a
 * generated directory from a static one and would lose the task dependency.
 * The Variant API below is the supported way to say "generated", and it carries
 * the dependency, so a build that changed a Rust export cannot package a stale
 * library.
 */
abstract class StageJniLibraries : DefaultTask() {
    /**
     * The ABI directory name of each built library, keyed by its path.
     *
     * It is one map rather than a file collection beside a list of names. A
     * `ConfigurableFileCollection` iterates in unspecified order, so pairing it
     * with a parallel list would package a library under the wrong ABI whenever
     * that order changed, and an APK whose arm64 directory holds an x86 library
     * fails at `System.loadLibrary` on a device and nowhere earlier.
     */
    @get:Input
    abstract val librariesByAbi: MapProperty<String, String>

    /** The same files, so Gradle can tell when the build is up to date. */
    @get:InputFiles
    abstract val libraries: ConfigurableFileCollection

    /** The staged `jniLibs` tree. */
    @get:OutputDirectory
    abstract val output: DirectoryProperty

    @TaskAction
    fun stage() {
        val destination = output.get().asFile
        destination.deleteRecursively()
        librariesByAbi.get().forEach { (abi, path) ->
            val library = File(path)
            if (!library.exists()) {
                throw GradleException("no JNI adapter for $abi at $path")
            }
            val directory = destination.resolve(abi).apply { mkdirs() }
            library.copyTo(directory.resolve("libchur_jni.so"), overwrite = true)
        }
    }
}

val stageJniLibraries =
    tasks.register<StageJniLibraries>("stageJniLibraries") {
        dependsOn(cargoBuildAndroid)
        val byAbi =
            androidAbis.mapValues { (_, triple) ->
                cargoTargetDirectory.file("$triple/release/libchur_jni.so").asFile.absolutePath
            }
        librariesByAbi.set(byAbi)
        libraries.setFrom(byAbi.values)
        output.set(layout.buildDirectory.dir("chur-jni"))
    }

androidComponents {
    onVariants { variant ->
        variant.sources.jniLibs?.addGeneratedSourceDirectory(
            stageJniLibraries,
            StageJniLibraries::output,
        )
    }
}
