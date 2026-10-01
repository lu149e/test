# Despliegue reproducible

## Binario

```bash
cargo build --release --locked -p uad-cli     # Rust ≥ 1.88; Cargo.lock versionado
install -m 0755 target/release/uad /usr/local/bin/uad
```

Linux y Windows (x86_64/aarch64). Dependencias de ejecución opcionales: Java 17+ con
`keytool` (bundletool), Android SDK (solo para el emulador). Compilar sin emulador:
`cargo build --release -p uad-cli --no-default-features`.

## Docker

```bash
docker build -t uad .
# Si Docker Hub limita las peticiones: --build-arg REGISTRY=mirror.gcr.io/library
# Detrás de un proxy con inspección TLS: --secret id=ca,src=ca.pem
export UAD_API_TOKEN=$(openssl rand -hex 32) UAD_MASTER_KEY=$(openssl rand -hex 32)
docker compose -f deploy/docker-compose.yml up -d
```

La imagen: etapa de compilación `rust:1.94-bookworm` con `--locked`; ejecución en
`eclipse-temurin:21-jre-noble` (JRE + keytool para bundletool, certificados CA), usuario sin
privilegios `uad` (UID 10001), datos en el volumen `/var/lib/uad`, configuración en
`/etc/uad/uad.toml` ([`deploy/uad.docker.toml`](../deploy/uad.docker.toml)). El *compose*
monta el sistema de archivos de solo lectura, elimina capacidades y publica el puerto solo en
`127.0.0.1`. Comprobado en el entorno de desarrollo: construcción de la imagen, adquisición
real desde F-Droid y AAB → APK universal (con descarga y verificación de bundletool) dentro
del contenedor.

Uso puntual sin servidor:

```bash
docker run --rm -v uad-data:/var/lib/uad uad get "https://play.google.com/store/apps/details?id=org.videolan.vlc" --out /var/lib/uad/out
```

## systemd

```bash
useradd -r -d /var/lib/uad uad
install -D -m 0644 uad.example.toml /etc/uad/uad.toml     # data_dir = "/var/lib/uad"
install -m 0600 /dev/null /etc/uad/uad.env                 # UAD_MASTER_KEY=… UAD_API_TOKEN=…
install -m 0644 deploy/uad.service /etc/systemd/system/uad.service
systemctl enable --now uad
```

## Windows

El ejecutable precompilado se obtiene del workflow `build` (Actions → build → Artifacts →
`uad-main-windows-x86_64`); se enlaza con el CRT estático, así que no necesita el
Visual C++ Redistributable. Para compilarlo:

```powershell
cargo build --release --locked -p uad-cli
$env:UAD_MASTER_KEY = "<64 hex>"; .\target\release\uad.exe --data-dir C:\ProgramData\uad serve
```

Para ejecutarlo como servicio puede usarse el Programador de tareas o NSSM con una cuenta de
servicio dedicada; los permisos del directorio de datos deben restringirse a esa cuenta. La
suite completa de tests se ejecuta en `windows-latest` en la CI.

### Smart App Control (Windows 11)

Smart App Control bloquea los ejecutables sin firma de código que Microsoft no reconoce.
Afecta a la compilación local (Cargo ejecuta scripts de build recién compilados; error
`failed to run custom build command`) y puede afectar también al `.exe` descargado, que no
está firmado. Alternativas:

* **WSL** (mantiene la protección activa):
  ```powershell
  wsl --install -d Ubuntu
  ```
  En Ubuntu:
  ```bash
  sudo apt update && sudo apt install -y build-essential git openjdk-21-jre-headless
  curl https://sh.rustup.rs -sSf | sh -s -- -y && . ~/.cargo/env
  git clone https://github.com/lu149e/test.git uad && cd uad
  cargo build --release -p uad-cli && ./target/release/uad serve
  ```
  La interfaz se abre desde el navegador de Windows en <http://127.0.0.1:8080>.
* **Desactivar Smart App Control** (Seguridad de Windows → Control de aplicaciones y
  navegador). En muchas versiones de Windows 11 no se puede reactivar sin reinstalar.
* **Firmar el ejecutable** con un certificado de firma de código (fuera del alcance de este
  repositorio).

## Operación

* `uad provenance verify` periódicamente (o `GET /api/provenance/verify`) y copia de
  `keys/provenance.pub` fuera del host.
* Copias de seguridad: `uad.sqlite3` (con la base detenida o `sqlite3 .backup`), `objects/`,
  `keys/` y `secrets.enc`. Sin `UAD_MASTER_KEY` ni `keys/master.key` los secretos no se pueden
  descifrar.
* Registros: `RUST_LOG=info` (por defecto) o `debug`; los secretos nunca se registran.
* Actualizar bundletool: cambiar `bundletool.download_url` y `bundletool.jar_sha256`.
