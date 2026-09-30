# API HTTP

Base: `http://127.0.0.1:8080`. Si `UAD_API_TOKEN` está definido, todas las rutas `/api/*`
salvo `/api/health` requieren `Authorization: Bearer <token>` (o `?token=` en enlaces de
descarga). Respuestas JSON; errores como `{"error": "..."}` con 400/401/404/409/413/500.

| Método y ruta | Descripción |
|---|---|
| `GET /api/health` | Versión, número de trabajos y archivos, si se requiere token |
| `GET /api/providers` | `ProviderInfo[]`: id, nombre, tipo, habilitado, prioridad, estado |
| `POST /api/jobs` | Crea un trabajo: `{"input": "<url o paquete>", "options": JobOptions?}` → `202 {"id"}` |
| `GET /api/jobs?limit=&package=` | Lista resumida |
| `GET /api/jobs/{id}` | Trabajo, historial de estados e informe (`report`) |
| `POST /api/jobs/{id}/retry` | Reencola un trabajo terminal |
| `POST /api/jobs/{id}/cancel` | Cancela (inmediato si está en cola; entre fases si se ejecuta) |
| `GET /api/jobs/{id}/sets/{n}/apks` | Descarga el conjunto de splits `n` como `.apks` (solo si todos sus miembros están verificados) |
| `GET /api/artifacts/{sha256}` | Descarga un archivo **verificado** (bytes originales) |
| `GET /api/artifacts/{sha256}/provenance` | Registros de procedencia del archivo y clave pública |
| `GET /api/provenance/verify` | Verifica la cadena completa |
| `POST /api/upload` | `multipart/form-data` con campo `file` (.apk/.aab/.apks/.xapk) → importa y crea un trabajo `local` |

`JobOptions`:

```json
{"version_code": null, "providers": ["fdroid"], "abis": ["arm64-v8a"],
 "all_variants": false, "build_universal_from_aab": true}
```

Estados: `queued`, `resolving`, `discovering`, `acquiring`, `processing`, `verifying`,
`completed`, `partially_completed`, `failed`, `cancelled`.

Informe (`report`), campos principales:

* `outcome`: `universal_original` | `universal_generated` | `split_set` | `variants` | `none`.
* `counts`: `known`, `identified`, `retrieved`, `failed`.
* `providers[]`: `status` = `offers` | `metadata_only` | `not_found` | `not_configured` |
  `denied` | `auth_error` | `error` | `timeout` | `skipped`.
* `variants[]`: `availability`, `kind` (`universal_apk`, `standalone_apk`, `base_apk`,
  `config_split`, `feature_split`, `generated_universal_apk`, `app_bundle`…), `origin`
  (`original` | `generated_from_aab`), `sha256`, `abis`, `signer_sha256`, `signature_schemes`,
  `checks[]` (`name`, `status`, `detail`), `provenance_seq`, `source` (sin credenciales).
* `split_sets[]`: miembros y `report` (`installable`, `abis`, `densities`, `languages`,
  `unmet_required_split_types`, `errors`).

Ejemplo:

```bash
curl -s -X POST localhost:8080/api/jobs -H 'content-type: application/json' \
  -d '{"input":"https://play.google.com/store/apps/details?id=org.videolan.vlc"}'
curl -s localhost:8080/api/jobs/<id> | jq '.state, .report.outcome, .report.counts'
curl -OJ localhost:8080/api/artifacts/<sha256>
```
