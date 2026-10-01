# Universal APK Downloader (`uad`)

Motor propio en Rust para **identificar** una aplicación a partir de su enlace de Google Play,
**descubrir** qué archivos son accesibles en fuentes oficiales o autorizadas, **descargarlos**,
**procesarlos** (AAB → APK universal con bundletool, conjuntos de splits → `.apks`),
**verificarlos** criptográficamente y **registrar su procedencia** de forma verificable.

No es un envoltorio de APKPure, APKMirror ni de ningún otro distribuidor de APK: no consulta
sus servidores. Reutiliza bibliotecas consolidadas (RustCrypto, rustls, SQLite, axum) y
herramientas oficiales (bundletool), pero el análisis de APK, la verificación de firmas
v1/v2/v3/v3.1, los clientes de las fuentes, el almacén, el orquestador y la procedencia son
implementación propia.

> **Qué no promete.** No existe acceso universal a todas las aplicaciones. Lo que se obtiene
> depende de qué fuentes están configuradas y de qué ofrece cada una para esa app, cuenta,
> país y perfil de dispositivo. El sistema no elude DRM, licencias ni controles de acceso,
> nunca compra apps de pago y distingue siempre entre variantes **conocidas**,
> **identificadas** y **recuperadas**. Consulta [docs/LIMITACIONES.md](docs/LIMITACIONES.md).

## Estado verificado

| Capacidad | Estado |
|---|---|
| Enlace de Play / `market://` / nombre de paquete → paquete validado | ✅ probado |
| Metadatos del listado público de Google Play (título, desarrollador, precio) | ✅ probado en vivo |
| Proveedor F-Droid con índice firmado (clave fijada, anti-rollback) | ✅ probado en vivo |
| Descarga reanudable (`Range`), reintentos, deduplicación por SHA-256 | ✅ probado (corte de conexión simulado) |
| Verificación de firmas v1 (JAR), v2, v3, v3.1, verity, rotación de clave | ✅ contrastado con `apksigner` en 15 fixtures y 16 APK reales |
| Detección de manipulación y de *stripping* de firmas | ✅ probado |
| AAB → APK universal con bundletool (firmado con clave local, marcado como generado) | ✅ probado con bundletool 1.18.3 |
| Validación de conjuntos de splits (`requiredSplitTypes`, firmante común…) y exportación `.apks` | ✅ probado |
| Ledger de procedencia encadenado y firmado (Ed25519) | ✅ probado (incluida detección de alteraciones) |
| API HTTP + interfaz web | ✅ probado E2E lanzando el binario |
| Imagen Docker (build + adquisición real + AAB→universal en contenedor) | ✅ probado |
| Google Play (protocolo de dispositivo, cuenta propia) | ⚠️ implementado; *checkin* validado en vivo con los 4 perfiles; **descarga autenticada no probada** (sin cuenta en este entorno) |
| Google Play Developer API (`generatedApks`, oficial) | ⚠️ implementado y con tests unitarios; **no probado en vivo** (requiere cuenta de desarrollador) |
| Emulador local opcional (AVD + `adb pull`) | ⚠️ implementado; **no probado** (sin KVM ni SDK de emulador aquí) |
| Windows | ⚠️ código multiplataforma y CI configurada para `windows-latest`; **no ejecutado aquí** |

## Descargar el ejecutable (sin compilar)

GitHub compila `uad` para Windows y Linux en cada cambio de `main`
(workflow [`build`](.github/workflows/release.yml)):

1. Ve a **Actions → build**, abre la ejecución más reciente en verde y, en **Artifacts**,
   descarga `uad-main-windows-x86_64` (o `linux-x86_64`). Las versiones etiquetadas (`v*`)
   se publican además en **Releases**.
2. Descomprime y, en esa carpeta, ejecuta `.\uad.exe serve` y abre <http://127.0.0.1:8080>.

Cada paquete incluye su SHA-256 y una atestación de procedencia de GitHub, verificable con
`gh attestation verify uad.exe --repo lu149e/test`.

> **Windows 11 con Smart App Control:** el `.exe` no está firmado con un certificado de
> firma de código, así que Smart App Control puede bloquearlo igual que bloquea la
> compilación local. En ese caso, usa WSL (ver [docs/DESPLIEGUE.md](docs/DESPLIEGUE.md)) o
> desactiva Smart App Control.

## Compilar desde el código

```bash
cargo build --release -p uad-cli          # Rust ≥ 1.88
./target/release/uad get "https://play.google.com/store/apps/details?id=de.danoeh.antennapod" --out ./apks
./target/release/uad serve                # http://127.0.0.1:8080
```

Salida real (resumida) del primer comando:

```
== de.danoeh.antennapod (completed)
   AntennaPod - Podcast Player — AntennaPod Open Source Team
   outcome: universal_original — Original universal APK retrieved and verified.
   provider play_web  metadata_only
   provider fdroid    offers
   [retrieved] de.danoeh.antennapod_3120295.apk UniversalApk
        source_digest    Pass: matches digest declared by fdroid (SHA-256)
        signature        Pass: valid APK signature (v3, v2, v1)
        declared_signer  Pass: signer matches F-Droid signed index (… cryptographically authenticated)
        signer_pin       Info: first time this signer is seen … pinned
```

Para una app sin APK universal (p. ej. `org.videolan.vlc` en F-Droid) el resultado es
`variants`: se recuperan y verifican las cuatro variantes por ABI y se listan las versiones
anteriores como *identificadas*.

Requisitos opcionales: Java 17+ para bundletool (se descarga y se comprueba su SHA-256
automáticamente) y `keytool` para la clave local de firma de APK generados.

### Comandos

| Comando | Descripción |
|---|---|
| `uad get <url\|paquete> [--out DIR] [--all-variants] [--provider P]… [--abi A]… [--version-code N] [--json]` | Adquiere en primer plano y copia los archivos verificados |
| `uad serve [--listen ADDR]` | Interfaz web + API + trabajadores en segundo plano |
| `uad analyze <archivo.apk\|.aab> [--json]` | Análisis y verificación offline |
| `uad verify-set <apk>…` | Comprueba que varios splits forman un conjunto instalable |
| `uad import <archivo>` | Copia un APK/AAB/APKS a la bandeja local |
| `uad providers` | Estado de los proveedores |
| `uad play-login --email <e>` | Guarda (cifrada) una cuenta de Google para el proveedor de Play |
| `uad secrets set\|list\|delete` | Secretos cifrados (nunca por línea de comandos) |
| `uad provenance verify\|show <sha256>` | Verificación del ledger de procedencia |
| `uad jobs`, `uad job <id>`, `uad config` | Consulta |

## Documentación

* [Arquitectura y decisiones](docs/ARQUITECTURA.md)
* [Seguridad, autenticidad y procedencia](docs/SEGURIDAD.md)
* [Proveedores: mecanismos, configuración y restricciones](docs/PROVEEDORES.md)
* [API HTTP](docs/API.md)
* [Limitaciones reales](docs/LIMITACIONES.md)
* [Despliegue](docs/DESPLIEGUE.md)
* Configuración de ejemplo: [`uad.example.toml`](uad.example.toml)

## Pruebas

```bash
cargo test --workspace --all-features                              # offline
UAD_TEST_BUNDLETOOL=/ruta/bundletool-all-1.18.3.jar cargo test -p uad-engine --test pipeline
cargo test -p uad-providers --test live_fdroid --test live_play -- --ignored   # red
scripts/gen-fixtures.sh    # regenera fixtures con aapt2/apksigner/bundletool oficiales
```

## Licencia

Apache-2.0. Los mensajes protobuf del protocolo de Google Play se declararon a mano tomando
como referencia de numeración de campos el `GooglePlay.proto` mantenido por la comunidad
(crate `googleplay-protobuf`, MIT).
