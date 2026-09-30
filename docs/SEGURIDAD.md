# Seguridad, autenticidad y procedencia

## Qué se garantiza y qué no

* **Se garantiza** (cuando un archivo aparece como `retrieved`): que sus bytes son
  exactamente los que entregó la fuente (digest declarado por la fuente cuando existe, y
  SHA-256 propio siempre), que su firma Android es criptográficamente válida, que el paquete y
  la versión son los esperados, que el firmante coincide con el declarado por la fuente (si la
  fuente lo declara) y con el fijado previamente para esa app y fuente, y que todo ello quedó
  registrado en un ledger encadenado y firmado.
* **No se garantiza**: que el código sea inocuo (no hay análisis de malware), ni que un APK
  con firma válida provenga de Google Play. Una firma solo prueba integridad e identidad de
  quien firmó. F-Droid, por ejemplo, suele firmar con su propia clave apps que en Play firma
  el desarrollador. La UI y la CLI muestran esta advertencia en cada archivo (`malware: info`).

## Verificación de firmas (propia, contrastada con `apksigner`)

Implementada en `uad-apk::sig` siguiendo la especificación de AOSP:

* **v2/v3/v3.1:** localización del *APK Signing Block* (tamaños de cabecera/pie coherentes,
  límites), EOCD sin ZIP64, directorio central contiguo al EOCD; por firmante: verificación de
  todas las firmas soportadas sobre *signed data*, igualdad de conjuntos de algoritmos entre
  digests y firmas, clave pública = clave del primer certificado, rango de SDK interno =
  externo (v3), digest de contenido por bloques de 1 MiB (SHA-256/SHA-512) y árbol *verity*
  (SHA-256, bloques de 4 KiB con sal de 8 bytes) sobre las tres secciones con el offset del
  directorio central sustituido.
* **Rotación de clave (v3 proof-of-rotation):** cada eslabón del linaje debe estar firmado
  por el certificado anterior con el algoritmo declarado, y el linaje debe terminar en el
  firmante actual. El linaje verificado se usa para aceptar cambios de clave legítimos.
* **v1 (JAR):** CMS/PKCS#7 sobre el `.SF` (con o sin atributos firmados y `messageDigest`),
  digest del manifiesto completo o por sección, digests de **cada** entrada del ZIP, entradas
  no listadas o no cubiertas, secciones duplicadas.
* **Anti-stripping:** `X-Android-APK-Signed` del `.SF` y el atributo de protección del
  bloque v2 obligan a que existan los bloques v2/v3 declarados.
* **Consistencia entre esquemas:** firmantes v1/v2 deben coincidir o pertenecer al linaje v3.
* **Otras defensas:** entradas ZIP duplicadas (confusión de nombres), datos antes de la
  primera entrada (estilo *Janus*, avisado), límites de tamaño y de descompresión.
* **Política de plataforma** (avisos, no errores de integridad): falta de v1 con
  `minSdk < 24`, solo v1 con `targetSdk ≥ 30`, RSA < 2048.

Criptografía: RustCrypto (RSA PKCS#1 v1.5 y PSS, ECDSA P-256/384/521, DSA, SHA-1/2, MD5 solo
para firmas v1 heredadas). Pruebas: `crates/uad-apk/tests/fixtures.rs` compara el veredicto
y los firmantes con los de `apksigner verify` para cada fixture (generados con `aapt2`,
`apksigner`, `jarsigner` y `bundletool`), incluyendo APK manipulados y sin bloque v2/v3.
Además se contrastaron 16 APK reales de F-Droid (v1 antiguos, v2, v3): 16/16 coincidencias.

## Política de verificación por archivo

`uad-engine::engine::verify_entry` produce comprobaciones con estado `pass/fail/warn/info`:

| Comprobación | Falla si… |
|---|---|
| `source_digest` | (lo impone el descargador) el SHA-256/SHA-1/tamaño no coincide con el declarado |
| `signature` | la firma no verifica (AAB sin firmar: aviso) |
| `package` / `version` | el manifiesto declara otro paquete o versionCode que el anunciado |
| `declared_signer` | el firmante (o su linaje) no coincide con el que declara la fuente |
| `signer_pin` | *TOFU*: el firmante difiere del fijado para (paquete, proveedor) sin prueba de rotación (fallo con `strict_signer_pinning = true`, aviso si no) |
| `classification` | aviso si la fuente dijo "universal" y el análisis dice otra cosa |
| `origin` / `malware` | informativas |

Solo los archivos sin `fail` pasan a `retrieved` y reciben registro de procedencia. **Los
archivos no verificados quedan en cuarentena**: están en el almacén (para análisis forense)
pero la API se niega a servirlos.

## Cadenas de confianza por fuente

* **F-Droid:** `entry.jar` firmado (v1) por la clave del repositorio, cuyo SHA-256 está
  **fijado** en la configuración → `entry.json` declara SHA-256 y tamaño de
  `index-v2.json` → el índice declara SHA-256 de cada APK y SHA-256 del certificado firmante.
  Anti-rollback: se rechaza un `entry.json` más antiguo que el último aceptado. Si la red
  falla, se usa el último índice verificado.
* **Google Play (protocolo de dispositivo):** canal TLS con la cuenta propia del operador;
  Play declara SHA-1/SHA-256 de cada archivo y los hashes de certificado del firmante
  (`certificateSet`); ambos se exigen. No es una aserción firmada: se marca
  `authenticated: false`.
* **Play Developer API:** API oficial sobre TLS con cuenta de servicio del propio
  desarrollador; declara el SHA-256 del certificado de firma de la app.
* **Local / emulador:** sin aserciones de la fuente; la autenticidad descansa en la firma, el
  *pinning* y, si procede, la comparación con otras fuentes.

## APK generados desde AAB

bundletool debe firmar lo que genera y las claves de firma del desarrollador o de Google Play
no están disponibles. Por eso se usa una **clave local dedicada**
(`CN=UAD Local Build Key (NOT an original signer)`), creada con `keytool` si no se configura
otra. El resultado se registra con `origin: generated_from_aab`, `derived_from: <sha256 del
AAB>`, versión de bundletool, y la UI lo marca como **GENERADO (no original)**. Nunca se
compara ni se fija contra el firmante original.

## Procedencia verificable

Cada archivo verificado genera un registro (`uad-engine::provenance`) con: paquete, versión,
SHA-256/SHA-1, tamaño, origen, tipo de variante, proveedor, canal, perfil de dispositivo,
URL de origen **sin credenciales** (las URL de Play se guardan sin *query*), comprobaciones y
firmantes. Los registros forman una cadena de hashes (cada uno incluye el hash del anterior) y
cada hash se firma con la clave Ed25519 de la instalación (`keys/provenance.ed25519`,
pública en `keys/provenance.pub`). `uad provenance verify` y `GET /api/provenance/verify`
detectan modificación, borrado o reordenación. Es una prueba de lo que *esta instalación*
observó, no una atestación de terceros.

## Credenciales y sesiones

* Nunca en el archivo de configuración ni en argumentos de línea de comandos
  (`uad secrets set` y `uad play-login` leen de un archivo o de la terminal sin eco).
* Almacén cifrado con ChaCha20-Poly1305 (`secrets.enc`). La clave maestra se toma de
  `UAD_MASTER_KEY` (recomendado: inyectada por systemd/Docker/gestor de secretos) o de
  `keys/master.key` con permisos 0600 (protege copias de seguridad y fugas parciales, no a un
  atacante con acceso completo al disco).
* Inyección de solo lectura por variables `UAD_SECRET_<CLAVE>`.
* Las sesiones de Play (id de dispositivo, tokens) se guardan en el mismo almacén cifrado.
* Cabeceras sensibles (cookies de descarga de Play, `Authorization`) están marcadas y su
  `Debug` las oculta; no se persisten ni se registran.

## Aislamiento de operaciones

* **Entradas no confiables:** todos los parsers (AXML, protobuf, ZIP, JAR, CMS) comprueban
  límites y devuelven error en lugar de entrar en pánico; tamaños máximos de manifiesto,
  archivos META-INF, descompresión total y descarga.
* **Contenedores `.apks/.xapk`:** se extraen aplanando nombres (sin *zip-slip*) a un
  directorio direccionado por contenido; los cifrados se rechazan.
* **Procesos externos:** bundletool, keytool y adb se ejecutan sin shell, con argumentos
  separados, tiempo límite y `kill_on_drop`; las contraseñas de keystore se pasan como
  `file:` a archivos 0600, nunca en la línea de comandos. El nombre de paquete que llega a
  `adb shell` está validado (`[A-Za-z0-9_.]`).
* **Servidor web:** escucha en `127.0.0.1` por defecto y se niega a escuchar en otra
  dirección sin `UAD_API_TOKEN`; comparación del token en tiempo constante; CSP estricta,
  `nosniff`, `DENY` de marcos; la UI construye el DOM con `textContent` (los metadatos
  externos no se interpretan como HTML); nombres de archivo saneados en
  `Content-Disposition`.
* **Despliegue:** imagen con usuario sin privilegios, sistema de archivos de solo lectura,
  sin capacidades; unidad systemd con `ProtectSystem=strict`, `NoNewPrivileges`, filtro de
  llamadas al sistema.

## Riesgos residuales conocidos

* El protocolo de dispositivo de Google Play no es una API pública documentada; su uso puede
  contravenir los Términos de Servicio de Google y la cuenta usada puede ser limitada. Está
  desactivado por defecto; úsese solo con cuentas propias y para apps gratuitas o adquiridas.
* El *pinning* TOFU no protege la primera descarga de una app: para ella, la protección son
  las aserciones de la fuente (índice firmado de F-Droid, `certificateSet` de Play).
* La clave de procedencia y la clave maestra en disco son tan seguras como el host.
