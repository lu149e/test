# Proveedores de adquisición

Orden de prioridad (menor = preferido): `play_web` 0 (solo metadatos) · `play_dev` 5 ·
`play` 10 · `fdroid` 20 · `local` 30 · `emulator` 40. `uad providers` muestra su estado.

## Mecanismos investigados y decisiones

| Mecanismo | Qué ofrece | Decisión |
|---|---|---|
| Ficha pública de Google Play (HTML + JSON-LD schema.org) | Existencia, nombre, desarrollador, icono, precio. Sin descargas ni versión. | Implementado (`play_web`), solo metadatos |
| **Google Play Developer API** (`androidpublisher v3`, `generatedapks`) | Para apps **de la propia cuenta de desarrollador**: APK universal, splits por variante y APK standalone **generados y firmados por Google Play** | Implementado (`play_dev`). Es el mecanismo oficial y autorizado que devuelve exactamente lo que Play distribuye |
| Protocolo de dispositivo de Play (`/checkin`, `/auth`, `/fdfe/details`, `purchase`, `delivery`) | Lo que Play entregaría a un dispositivo con la configuración declarada, con la cuenta del operador | Implementado (`play`), desactivado por defecto; solo apps gratuitas o ya adquiridas; ver riesgos |
| Repositorio F-Droid (índice v2 firmado) | APK de apps libres compiladas y firmadas por F-Droid (o reproducibles con firma del desarrollador) | Implementado (`fdroid`) con cadena de confianza completa |
| AAB propio del desarrollador | Bundle original | Entrada por bandeja local/subida (`local`); bundletool genera el universal |
| Emulador Android local | APK instalados en un AVD | Implementado como componente opcional (`emulator`) |
| Espejos de terceros (APKPure, APKMirror…) | — | **Excluidos** por requisito |
| Dispensadores de tokens de terceros | Cuentas anónimas compartidas | **Excluidos**: dependencia externa y cuentas ajenas |

## `play_web` — ficha pública

Sin configuración. Confirma que la app está en Play e informa del precio: si es de pago se
anota que solo es obtenible con una cuenta que la posea.

## `fdroid` — F-Droid

```toml
[providers.fdroid]
enabled = true
repo_url = "https://f-droid.org/repo"
fingerprint = "43238d512c1e5eb2d6569f4a3afbf5523418b82e0a3ed1552770abb9a9c9ccab"
include_prereleases = false
```

Funciona con cualquier repositorio F-Droid (p. ej. IzzyOnDroid o uno propio) cambiando URL y
huella. Selección: la versión estable más alta firmada por el `preferredSigner`; si esa
versión está publicada como builds por ABI (mismo `versionName`, un solo ABI cada uno), se
ofrecen todas como variantes (filtrables con `--abi`). Las versiones anteriores se informan
como *identificadas*. Primera ejecución: descarga ~60 MB de índice; luego solo `entry.jar`
cada `refresh_minutes`.

## `play` — Google Play con cuenta propia

```toml
[providers.play]
enabled = true
device_profiles = ["arm64", "armv7", "x86_64", "x86"]
```

1. Inicia sesión en <https://accounts.google.com/EmbeddedSetup> con la cuenta que se usará
   (se recomienda una cuenta dedicada que haya aceptado los términos de Google Play). Copia
   el valor de la cookie `oauth_token` (empieza por `oauth2_4/`); es de un solo uso.
2. `uad play-login --email tu@cuenta` (pide el token sin eco). Se intercambia por un token AAS
   de larga duración que se guarda cifrado.
3. Por cada perfil: *checkin* (id de dispositivo), `uploadDeviceConfig`, token de Play, `toc`;
   la sesión se guarda cifrada y se renueva si caduca.
4. Por app: `details` (versión, precio, `certificateSet`, lista de splits), `purchase` con
   `ot=1` **solo si el precio es 0**, `delivery` → base, splits, OBB y *dex metadata* con
   SHA-1/SHA-256 declarados y cookie de descarga.

**Variantes:** Play solo entrega los splits que corresponden al dispositivo declarado. Cada
perfil (ARM64, ARMv7, x86_64, x86, con su densidad y SDK) produce su propio conjunto; se
deduplican los archivos idénticos. Los splits que `details` enumera pero ningún perfil recibe
se informan como *conocidos*. Para densidades o idiomas concretos se pueden definir perfiles
adicionales en un archivo `.properties` (`profiles_file`, formato de Aurora Store).

**Verificado en este entorno:** el *checkin* anónimo con los cuatro perfiles integrados es
aceptado por `android.clients.google.com` (valida la codificación protobuf y los perfiles) y
un token inválido se reporta como `BadAuthentication`. **No verificado:** el flujo
autenticado completo (no se dispone de cuenta). Riesgos: protocolo no documentado sujeto a
cambios, posible huella TLS en `/auth`, y posibles restricciones sobre la cuenta; ver
[LIMITACIONES.md](LIMITACIONES.md).

## `play_dev` — Google Play Developer API (oficial)

```toml
[providers.play_dev]
enabled = true
track = "production"
```

```bash
uad secrets set play_dev.service_account_json --file service-account.json
```

La cuenta de servicio debe estar invitada en Play Console con permiso para la app. Si no se
indica `--version-code`, se abre una *edit* temporal para leer el `versionCode` más alto del
track configurado y se descarta. Se ofrece: APK universal (preferido), un conjunto de splits
por variante y los APK standalone. Todos están firmados por la clave de firma de apps de
Google Play, cuyo SHA-256 declara la API y se exige. **No probado en vivo** (requiere cuenta
de desarrollador).

## `local` — bandeja e importación

Archivos en `data/inbox/` (o subidos por la web / `uad import`): `.apk`, `.aab`, `.apks`,
`.xapk` (y `.apkm` no cifrados). Se agrupan por versión; un contenedor de splits forma un
conjunto. Es la vía para AAB propios → APK universal con bundletool.

## `emulator` — componente opcional

Compilado con la feature `emulator` (activa por defecto en el binario) y desactivado en
configuración:

```toml
[providers.emulator]
enabled = true
sdk_root = "/opt/android-sdk"
avd = "Pixel_API_34"      # o serial = "emulator-5554" para uno ya arrancado
```

Arranca el AVD sin ventana si hace falta, espera `sys.boot_completed`, localiza el paquete
con `pm path`, obtiene la versión con `dumpsys package` y hace `adb pull` de cada APK; al
terminar detiene el emulador si lo arrancó él. **No automatiza la Play Store** ni inicia
sesión en cuentas: la app debe haberse instalado previamente en el AVD por medios legítimos.
Un emulador x86_64 solo recibe splits x86_64. Requiere aceleración (KVM en Linux, WHPX en
Windows). **No probado aquí** (sin KVM).

## Añadir un proveedor

Implementar `uad_core::Provider` (`info()` y `discover()` devolviendo `Offer`s con
`RemoteFile`s, digests y `TrustAnchor` si la fuente declara firmante) y registrarlo en
`Engine::open`. Descarga, verificación, *pinning*, procedencia y UI no requieren cambios.
