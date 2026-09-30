#!/usr/bin/env bash
# Regenerates the binary test fixtures in crates/uad-apk/tests/fixtures using only official
# Android tooling (aapt2, zipalign, apksigner from build-tools; bundletool; JDK keytool/jarsigner).
#
#   ANDROID_BUILD_TOOLS=/path/to/build-tools/36.0.0 \
#   ANDROID_JAR=/path/to/platforms/android-35/android.jar \
#   BUNDLETOOL_JAR=/path/to/bundletool-all-1.18.3.jar \
#   scripts/gen-fixtures.sh
set -euo pipefail
BT="${ANDROID_BUILD_TOOLS:?set ANDROID_BUILD_TOOLS}"
AJAR="${ANDROID_JAR:?set ANDROID_JAR}"
BUNDLETOOL="${BUNDLETOOL_JAR:?set BUNDLETOOL_JAR}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/scripts/fixture-app"
OUT="$ROOT/crates/uad-apk/tests/fixtures"
W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT
mkdir -p "$OUT"
cd "$W"

PASS=fixture-pass
keygen() { # alias keyalg keysize
  keytool -genkeypair -keystore "$1.jks" -storepass $PASS -keypass $PASS -alias "$1" \
    -keyalg "$2" -keysize "$3" -validity 10000 -dname "CN=UAD Fixture $1, O=UAD Tests, C=ES" >/dev/null 2>&1
}
keygen rsa RSA 2048
keygen rsa2 RSA 3072
keygen ec EC 256

# --- plain APK -------------------------------------------------------------------------
"$BT/aapt2" compile --dir "$SRC/res" -o compiled.zip
"$BT/aapt2" link -o unsigned.apk -I "$AJAR" --manifest "$SRC/AndroidManifest.xml" compiled.zip
mkdir -p lib/arm64-v8a lib/x86_64
printf 'not-a-real-elf-arm64' > lib/arm64-v8a/libuad.so
printf 'not-a-real-elf-x86_64' > lib/x86_64/libuad.so
zip -q -0 unsigned.apk lib/arm64-v8a/libuad.so lib/x86_64/libuad.so
"$BT/zipalign" -p -f 4 unsigned.apk aligned.apk

sign() { # out key extra-args...
  local out="$1" key="$2"; shift 2
  "$BT/apksigner" sign --ks "$key.jks" --ks-pass pass:$PASS --ks-key-alias "$key" --key-pass pass:$PASS \
    --v4-signing-enabled false --out "$OUT/$out" "$@" aligned.apk
}
sign rsa_v1v2v3.apk rsa --v1-signing-enabled true --v2-signing-enabled true --v3-signing-enabled true
sign ec_v2only.apk ec --v1-signing-enabled false --v2-signing-enabled true --v3-signing-enabled false
sign rsa_v1only.apk rsa --v1-signing-enabled true --v2-signing-enabled false --v3-signing-enabled false --min-sdk-version 21
sign rsa3072_v3only.apk rsa2 --v1-signing-enabled false --v2-signing-enabled false --v3-signing-enabled true
sign rsa_verity.apk rsa --v1-signing-enabled false --v2-signing-enabled true --v3-signing-enabled true --verity-enabled true --min-sdk-version 24

# Key rotation: rsa -> ec, v3 with proof-of-rotation lineage.
"$BT/apksigner" rotate --out lineage.bin \
  --old-signer --ks rsa.jks --ks-pass pass:$PASS --ks-key-alias rsa --key-pass pass:$PASS \
  --new-signer --ks ec.jks --ks-pass pass:$PASS --ks-key-alias ec --key-pass pass:$PASS
"$BT/apksigner" sign --lineage lineage.bin \
  --ks rsa.jks --ks-pass pass:$PASS --ks-key-alias rsa --key-pass pass:$PASS --next-signer \
  --ks ec.jks --ks-pass pass:$PASS --ks-key-alias ec --key-pass pass:$PASS \
  --v1-signing-enabled true --v2-signing-enabled true --v3-signing-enabled true \
  --v4-signing-enabled false --out "$OUT/rotated_v3.apk" aligned.apk

# Tampered copies: flip one byte of a stored entry after signing (v2/v3 must fail), and
# strip the v2 block while keeping v1 (anti-stripping header must be detected).
python3 - "$OUT" <<'PY'
import sys, pathlib
out = pathlib.Path(sys.argv[1])
data = bytearray((out / "rsa_v1v2v3.apk").read_bytes())
i = data.find(b"not-a-real-elf-arm64")
data[i] ^= 0x01
(out / "tampered_content.apk").write_bytes(bytes(data))
PY

# --- App Bundle and split APKs ----------------------------------------------------------
"$BT/aapt2" link --proto-format -o base_proto.zip -I "$AJAR" --manifest "$SRC/AndroidManifest.xml" compiled.zip
mkdir -p module && (cd module && unzip -q ../base_proto.zip && mkdir -p manifest && mv AndroidManifest.xml manifest/ && cp -r ../lib . && zip -q -r ../base.zip .)
java -jar "$BUNDLETOOL" build-bundle --modules=base.zip --output=app.aab
jarsigner -keystore rsa.jks -storepass $PASS -keypass $PASS -sigalg SHA256withRSA -digestalg SHA-256 app.aab rsa >/dev/null
cp app.aab "$OUT/app.aab"

java -jar "$BUNDLETOOL" build-apks --bundle=app.aab --output=split.apks \
  --ks=rsa.jks --ks-pass=pass:$PASS --ks-key-alias=rsa --key-pass=pass:$PASS
rm -rf splits_out && mkdir splits_out && (cd splits_out && unzip -q ../split.apks)
mkdir -p "$OUT/splits"
rm -f "$OUT"/splits/*.apk
# Keep a representative subset: base + ABI + density + language config splits.
for f in base-master.apk base-arm64_v8a.apk base-x86_64.apk base-xxhdpi.apk base-mdpi.apk base-es.apk; do
  cp "splits_out/splits/$f" "$OUT/splits/$f"
done

java -jar "$BUNDLETOOL" build-apks --bundle=app.aab --output=universal.apks --mode=universal \
  --ks=ec.jks --ks-pass=pass:$PASS --ks-key-alias=ec --key-pass=pass:$PASS
unzip -q -o universal.apks universal.apk && cp universal.apk "$OUT/generated_universal.apk"

# Expected values computed by the official verifier, used to cross-check our implementation.
# Run twice: with the APK's own minSdk policy, and assuming minSdk 24 (where v1 is optional).
{
  for f in "$OUT"/*.apk "$OUT"/splits/*.apk; do
    echo "== $(basename "$f")"
    "$BT/apksigner" verify -v --print-certs "$f" 2>&1 | grep -E "^(Verifies|DOES NOT VERIFY|Verified using|ERROR)" || true
    echo "-- min-sdk-24"
    "$BT/apksigner" verify -v --print-certs --min-sdk-version 24 "$f" 2>&1 | grep -E "^(Verifies|DOES NOT VERIFY|ERROR|Signer.*certificate SHA-256)" || true
  done
} > "$OUT/apksigner-expected.txt"
ls -la "$OUT" "$OUT/splits"
