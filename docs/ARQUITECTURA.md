# Arquitectura

## Principios

1. **Monolito modular.** Un único binario (`uad`) con límites de módulo impuestos por el
   compilador mediante cinco crates. Sin microservicios, colas externas ni bases de datos de
   servidor: SQLite + sistema de archivos bastan para una instalación propia y simplifican el
   despliegue reproducible.
2. **Los proveedores descubren; el motor adquiere.** Ningún proveedor escribe en el almacén.
   Devuelven *ofertas* (archivos concretos con URL, cabeceras, tamaño, digests y firmante
   declarados). Descarga, verificación, clasificación y procedencia son comunes, así que cada
   fuente nueva hereda automáticamente reanudación, deduplicación y las mismas comprobaciones.
3. **Máquina de estados explícita y persistida.** Ninguna transición implícita; la
   verificación no se puede saltar (está en la tabla de transiciones y probado).
4. **Los originales son inmutables.** Los archivos se almacenan por SHA-256, en solo lectura,
   y se sirven byte a byte. Nada se re-firma; lo generado se etiqueta como generado.
5. **Honestidad en los resultados.** Cada variante tiene una disponibilidad
   (`known` → `identified` → `retrieved` | `failed`) y cada comprobación queda registrada.

## Crates

```
uad-core       Dominio sin E/S: PackageName y parseo de enlaces, variantes (ABI, densidad,
               idioma, base/config/feature), ofertas, contrato Provider, SecretStore,
               máquina de estados JobState.
uad-apk        Formato y criptografía: AXML (manifiesto binario), XML protobuf de AAB,
               manifiesto tipado, verificación v1/v2/v3/v3.1 (+verity, linaje de rotación),
               certificados, análisis/clasificación, validación de splits, escritor .apks.
uad-providers  Fuentes: play_web (listado público), play (protocolo de dispositivo),
               play_dev (Developer API oficial), fdroid (índice firmado), local (bandeja),
               emulator (feature opcional).
uad-engine     Configuración, secretos cifrados, almacén CAS + SQLite, descargador,
               bundletool, ledger de procedencia, política de verificación y orquestador.
uad-cli        Binario `uad`: CLI (clap), API HTTP y UI embebida (axum).
```

Dependencias: `core ← apk ← providers ← engine ← cli` (y `core` en todos). `uad-apk` no tiene
red ni asincronía; se puede usar como biblioteca de verificación independiente.

**Por qué no más crates:** el almacén, el descargador y el orquestador cambian juntos y no se
reutilizan por separado; dividirlos añadiría interfaces sin beneficio. **Por qué no menos:**
separar `uad-apk` permite probar la criptografía sin red; separar `uad-providers` impide por
construcción que un proveedor toque el almacén o la política de verificación.

**Traits:** solo dos, ambos con múltiples implementaciones reales: `Provider`
(6 implementaciones) y `SecretStore` (archivo cifrado y memoria para tests). El resto son
tipos concretos.

## Flujo de un trabajo

```
Queued ─Start→ Resolving ─Resolved→ Discovering ─OffersFound→ Acquiring ─Acquired→ Processing
                                                                                      │ Processed
Completed ←Verified(All)─ Verifying ←─────────────────────────────────────────────────┘
PartiallyCompleted ←Verified(Partial)─┘   Failed ←Verified(None) / Fail   Cancelled ←Cancel
Failed/Cancelled/PartiallyCompleted ─Retry→ Queued        (estado activo tras reinicio) ─Retry→ Queued
```

* **Resolving:** enlace → `PackageName` validado (reglas de applicationId; rechaza hosts
  ajenos, rutas, esquemas `file:` etc.).
* **Discovering:** todos los proveedores habilitados en paralelo con tiempo límite. Se
  combinan metadatos (por prioridad) y se registran *todas* las ofertas como variantes
  `identified` y lo que los proveedores conocen pero no ofrecen como `known`.
* **Plan:** 1) APK universal original (por prioridad de proveedor; los siguientes son
  alternativas si la descarga falla); 2) si no hay, AAB para bundletool; 3) si no, todos los
  conjuntos de splits y APK por ABI. `--all-variants` añade el resto.
* **Acquiring:** descargas concurrentes limitadas por semáforo, reanudables, con digest y
  tamaño declarados obligatorios cuando la fuente los da.
* **Processing:** análisis (caché por SHA-256), AAB → universal con bundletool, validación de
  conjuntos de splits.
* **Verifying:** política por archivo (ver [SEGURIDAD.md](SEGURIDAD.md)); solo lo que supera
  la política pasa a `retrieved`, recibe registro de procedencia y se puede descargar.

Cada transición se escribe en `jobs` + `job_events` antes de empezar la fase siguiente. Al
arrancar, los trabajos en estados activos vuelven a `Queued` (evento *recovered after
restart*) y se reprocesan; la descarga se reanuda desde el `.part` existente y lo ya
almacenado se deduplica.

## Concurrencia

* `max_concurrent_jobs` trabajadores tokio consumen una cola mpsc.
* `max_concurrent_downloads` permisos de semáforo compartidos por todos los trabajos.
* El proveedor de Play serializa su conversación por cuenta (mutex) y aplica un retardo
  configurable entre peticiones.
* El análisis de APK (CPU/E/S síncrona) se ejecuta en `spawn_blocking`.
* SQLite en modo WAL con un único `Connection` protegido por mutex: las operaciones son
  pequeñas y el cuello de botella real es la red.

## Almacenamiento

```
data/
  uad.sqlite3            jobs, job_events, artifacts (+análisis en caché), signer_pins, provenance
  objects/ab/cdef…       archivos por SHA-256, solo lectura, deduplicados
  tmp/                   descargas parciales (*.part) e importaciones
  cache/fdroid/…         entry.jar verificado + índice compacto
  cache/local-extracted  contenido de contenedores .apks/.xapk
  inbox/                 bandeja de importación local
  exports/<job>/         archivos .apks generados bajo demanda
  keys/                  master.key, provenance.ed25519(+.pub), clave local de bundletool
  tools/                 bundletool descargado (SHA-256 fijado)
  secrets.enc            secretos cifrados (ChaCha20-Poly1305)
```

## Implementación propia frente a reutilización

| Propio | Reutilizado (y por qué) |
|---|---|
| Parser AXML y de XML protobuf de AAB, modelo de manifiesto | `zip` para leer entradas (deflate) |
| Localización del APK Signing Block, digests por bloques de 1 MiB, árbol verity | RustCrypto: `sha1/sha2/md-5`, `rsa`, `p256/p384/p521`, `dsa`, `ed25519-dalek`, `chacha20poly1305` — nunca reimplementar primitivas |
| Verificación v1/v2/v3/v3.1, linaje de rotación, anti-stripping, consistencia entre esquemas | `x509-cert`, `cms`, `der`, `spki` para ASN.1 |
| Cliente del protocolo de Play (checkin, auth, details, delivery) y perfiles de dispositivo | `prost` para codificar protobuf |
| Cliente de la Play Developer API (JWT RS256 propio) | `reqwest` + `rustls` |
| Proveedor F-Droid con cadena de confianza completa | — |
| Descargador reanudable, almacén CAS, ledger, orquestador | `rusqlite` (SQLite embebido), `tokio`, `axum` |
| — | **bundletool** oficial de Google para AAB → APK (Java, JAR con SHA-256 fijado) |

## API pública

La API HTTP (ver [API.md](API.md)) es el contrato de integración estable: JSON sobre HTTP con
token Bearer. Los tipos serializados (`JobReport`, `VariantEntry`, `Check`, `ProviderInfo`)
viven en `uad-engine::report` y `uad-core` y son los mismos que usa la CLI con `--json`.

## Multiplataforma

Sin dependencias nativas salvo SQLite (compilado con `bundled`) y TLS en Rust puro
(`rustls` + almacén de certificados del sistema). Rutas con `Path`, nombres de ejecutables
con sufijo `.exe` en Windows, permisos restrictivos de archivos en Unix (en Windows se heredan
las ACL del perfil del usuario del servicio). El emulador es una *feature* de compilación y
además está desactivado por configuración.
