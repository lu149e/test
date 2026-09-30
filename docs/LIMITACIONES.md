# Limitaciones reales

Este documento separa lo **comprobado**, lo **implementado pero no comprobado** y lo que
**no puede garantizarse**.

## Comprobado (ejecutado en el entorno de desarrollo)

* Enlace de Google Play → ficha pública (metadatos) + F-Droid → descarga → verificación →
  exportación, con apps reales: AntennaPod (APK universal original) y VLC (sin universal en
  F-Droid: 4 APK por ABI recuperados y verificados, versiones anteriores identificadas).
* Cadena de confianza de F-Droid con clave fijada; rechazo de una clave incorrecta.
* Verificador de firmas frente a `apksigner` (build-tools 36): 15 fixtures generados con
  herramientas oficiales (v1, v2, v3, v3.1 con rotación, verity, RSA 2048/3072, EC P-256,
  bundletool, manipulados, sin bloque v2/v3) y 16 APK reales de F-Droid: coincidencia total
  en veredicto y firmantes.
* AAB → APK universal con bundletool 1.18.3 (firmado con clave local, marcado como generado).
* Descarga interrumpida y reanudada con `Range`; rechazo por digest incorrecto; deduplicación.
* Recuperación de un trabajo interrumpido tras reinicio.
* *Pinning* de firmante: un cambio de clave sin prueba de rotación hace fallar el trabajo.
* Ledger de procedencia: detección de un registro alterado.
* Servidor HTTP real: token, subida, verificación, descarga byte a byte, procedencia.
* *Checkin* anónimo contra `android.clients.google.com` con los 4 perfiles de dispositivo.

## Implementado, no comprobado de extremo a extremo

* **Descarga desde Google Play con cuenta** (`play`): requiere una cuenta de Google; el
  intercambio `oauth_token → AAS`, el token de Play, `details`, `purchase` y `delivery` están
  implementados según el protocolo documentado por proyectos de la comunidad, pero no se han
  ejecutado con credenciales reales. Riesgos concretos: cambios del protocolo sin aviso,
  rechazo por huella TLS en `/auth` (se ha observado con clientes no Android), verificación
  adicional de la cuenta, restricciones por país o por dispositivo, límites de peticiones.
* **Google Play Developer API** (`play_dev`): JWT, *edits* y `generatedApks` implementados y
  probados con datos simulados; no ejecutado contra la API real.
* **Emulador** (`emulator`): gestión de AVD y extracción por `adb` implementadas; no
  ejecutadas (sin KVM ni imágenes de sistema aquí).
* **Windows:** el código evita dependencias específicas de plataforma y la CI incluye
  `windows-latest`, pero no se ha ejecutado en Windows.

## No garantizable

* **Acceso universal.** No todas las apps son obtenibles: las de pago requieren una cuenta que
  las posea; muchas solo están en Play; otras están restringidas por país, dispositivo o edad;
  F-Droid solo tiene software libre.
* **APK universal "original" de Play.** Google Play no distribuye un APK universal a
  dispositivos modernos: entrega splits. El universal original solo existe si la fuente lo
  publica (F-Droid, desarrollador) o vía Developer API para apps propias. Un universal
  generado desde AAB **no es original** ni está firmado por el desarrollador.
* **Todas las variantes.** Play entrega solo los splits del dispositivo declarado; se cubren
  los perfiles configurados (ARM64, ARMv7, x86, x86_64 por defecto), pero densidades,
  idiomas, niveles de SDK o *feature modules* bajo demanda concretos pueden requerir perfiles
  adicionales o no estar disponibles. Los módulos de *Play Feature Delivery* bajo demanda y
  los *asset packs* no se solicitan por separado.
* **Emulador ≠ acceso completo.** Un emulador solo recibe lo que Play entregaría a esa
  configuración; no se automatiza la Play Store.
* **Firma válida ≠ seguro ni ≠ de Play.** No hay análisis de malware; la firma solo prueba
  integridad e identidad del firmante.
* **Primera descarga (TOFU).** El *pinning* protege cambios posteriores, no la primera
  observación; esa depende de las aserciones de la fuente.
* **Términos de servicio.** El protocolo de dispositivo de Play no es una API pública; su uso
  puede contravenir los términos de Google. Está desactivado por defecto.

## Funcionalidad fuera de alcance por ahora

* Formato `.apks` de bundletool (`toc.pb`): se genera un ZIP de splits con índice JSON
  propio, instalable con `adb install-multiple` o instaladores de splits.
* Descarga de versiones antiguas desde Play (depende de `vc`; Play suele servir solo la
  actual).
* OBB y *dex metadata* se descargan si Play los ofrece, pero no se validan más allá del
  digest declarado.
* Resolución de recursos (`resources.arsc`) para mostrar etiquetas de la app desde el APK.
