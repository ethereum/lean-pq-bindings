#!/bin/sh
# Prove the published artifact works as a dependency: publish io.github.crate-crypto:lean-pq to a
# throwaway Maven repository, resolve it from there in a fresh modular Gradle project, and run that
# project on the module path with --enable-native-access=org.ethereum.leanpq and no
# lean.pq.native.path, so the native library is the one bundled in the jar.
# Arguments go to the publishing build, e.g. -Pversion=1.2.3 -PleanPqNativeDir=DIR.
# GRADLE names the Gradle command (default `gradle`); JAVA_HOME selects the JDK 25 to run with.
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
gradle=${GRADLE:-gradle}
java=${JAVA_HOME:+$JAVA_HOME/bin/}java
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
repo="$work/repo"
consumer="$work/consumer"

"$gradle" -p "$script_dir/.." publishToMavenLocal -Dmaven.repo.local="$repo" "$@"
version=$(ls "$repo/io/github/crate-crypto/lean-pq" | grep -v '^maven-metadata')
published="$repo/io/github/crate-crypto/lean-pq/$version/lean-pq-$version.jar"
echo "published io.github.crate-crypto:lean-pq:$version; bundled natives:"
unzip -Z1 "$published" | grep '^org/ethereum/leanpq/native/.*/liblean_pq_native\.'

mkdir -p "$consumer/src/main/java/consumer"
cat > "$consumer/settings.gradle.kts" <<EOF
rootProject.name = "consumer"
dependencyResolutionManagement {
    // Only the throwaway repository: the artifact must resolve from what was just published.
    repositories { maven { url = uri("$repo") } }
}
EOF
cat > "$consumer/build.gradle.kts" <<EOF
plugins { application }
java { toolchain { languageVersion = JavaLanguageVersion.of(25) } }
dependencies { implementation("io.github.crate-crypto:lean-pq:$version") }
application {
    mainModule = "consumer"
    mainClass = "consumer.Main"
}
EOF
cat > "$consumer/src/main/java/module-info.java" <<'EOF'
module consumer {
    requires org.ethereum.leanpq;
}
EOF
cat > "$consumer/src/main/java/consumer/Main.java" <<'EOF'
package consumer;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import org.ethereum.leanpq.Aggregate;
import org.ethereum.leanpq.LeanPq;
import org.ethereum.leanpq.SignatureClaim;
import org.ethereum.leanpq.SignedMessage;
import org.ethereum.leanpq.SphincsSecretKey;
import org.ethereum.leanpq.XmssSecretKey;

public final class Main {
    public static void main(String[] args) throws Exception {
        check(System.getProperty("lean.pq.native.path") == null, "lean.pq.native.path must not be set");
        Module module = LeanPq.class.getModule();
        check(module.isNamed() && module.isNativeAccessEnabled(), "org.ethereum.leanpq must be a named module with native access");

        byte[] message = filled(0x42);
        byte[] other = filled(0x43);
        try (XmssSecretKey xmss = XmssSecretKey.fromSeed(filled(1));
             SphincsSecretKey sphincs = SphincsSecretKey.fromSeed(filled(2), 4)) {
            byte[] xmssSignature = xmss.sign(message, 0);
            check(LeanPq.xmssVerify(xmss.publicKey(), message, xmssSignature), "leanXMSS signature must verify");
            check(!LeanPq.xmssVerify(xmss.publicKey(), other, xmssSignature), "leanXMSS signature must not verify another message");
            byte[] sphincsSignature = sphincs.sign(message);
            check(LeanPq.sphincsVerify(sphincs.publicKey(), message, sphincsSignature), "leanSPHINCS signature must verify");
            check(!LeanPq.sphincsVerify(sphincs.publicKey(), other, sphincsSignature), "leanSPHINCS signature must not verify another message");

            try (Aggregate aggregate = LeanPq.aggregate(
                     List.of(),
                     List.of(new SignedMessage(xmss.publicKey(), message, xmssSignature)),
                     List.of(new SignedMessage(sphincs.publicKey(), message, sphincsSignature)));
                 Aggregate received = Aggregate.fromBytes(aggregate.toBytes())) {
                check(received.xmssClaims().equals(List.of(new SignatureClaim(xmss.publicKey(), message))), "aggregate must attest the leanXMSS claim");
                check(received.sphincsClaims().equals(List.of(new SignatureClaim(sphincs.publicKey(), message))), "aggregate must attest the leanSPHINCS claim");
            }
        }

        System.out.println("module " + module.getName() + " loaded from " + LeanPq.class.getProtectionDomain().getCodeSource().getLocation());
        Path maps = Path.of("/proc/self/maps");
        if (Files.exists(maps)) {
            String mapped = Files.readAllLines(maps).stream()
                .filter(line -> line.contains("liblean_pq_native"))
                .map(line -> line.substring(line.indexOf('/')))
                .findFirst()
                .orElseThrow(() -> new AssertionError("liblean_pq_native is not mapped"));
            System.out.println("native library mapped from " + mapped);
        }
        System.out.println("signed and verified with leanXMSS and leanSPHINCS, aggregated both");
    }

    private static byte[] filled(int value) {
        byte[] bytes = new byte[32];
        Arrays.fill(bytes, (byte) value);
        return bytes;
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
EOF

"$gradle" -p "$consumer" installDist
lib="$consumer/build/install/consumer/lib"
cmp "$published" "$lib/lean-pq-$version.jar"
# --illegal-native-access=deny turns a missing or misnamed native-access grant into an error.
"$java" --enable-native-access=org.ethereum.leanpq --illegal-native-access=deny -p "$lib" -m consumer/consumer.Main
echo "consumer ran against io.github.crate-crypto:lean-pq:$version"
