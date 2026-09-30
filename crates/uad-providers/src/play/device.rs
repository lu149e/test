//! Device profiles used when talking to Google Play as an Android device.
//!
//! Google Play selects APKs/splits for the *declared* device configuration (ABIs, screen
//! density, SDK level, locales, features). Querying with several profiles is how the provider
//! discovers ABI/density-specific variants without physical devices. The profile format is the
//! widely used `.properties` layout (e.g. files exported by Aurora Store's spoof manager), so
//! operators can supply profiles of real devices; the built-in ones are generic.

use super::proto::{AndroidBuildProto, AndroidCheckinProto, DeviceConfigurationProto, DeviceFeature};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq)]
pub struct DeviceProfile {
    pub name: String,
    pub props: BTreeMap<String, String>,
}

const COMMON_FEATURES: &str = "android.hardware.audio.output,android.hardware.bluetooth,android.hardware.bluetooth_le,android.hardware.camera,android.hardware.camera.any,android.hardware.camera.autofocus,android.hardware.camera.flash,android.hardware.camera.front,android.hardware.faketouch,android.hardware.location,android.hardware.location.gps,android.hardware.location.network,android.hardware.microphone,android.hardware.nfc,android.hardware.opengles.aep,android.hardware.ram.normal,android.hardware.screen.landscape,android.hardware.screen.portrait,android.hardware.sensor.accelerometer,android.hardware.sensor.compass,android.hardware.sensor.gyroscope,android.hardware.sensor.light,android.hardware.sensor.proximity,android.hardware.telephony,android.hardware.telephony.gsm,android.hardware.touchscreen,android.hardware.touchscreen.multitouch,android.hardware.touchscreen.multitouch.distinct,android.hardware.touchscreen.multitouch.jazzhand,android.hardware.usb.accessory,android.hardware.usb.host,android.hardware.vulkan.compute,android.hardware.vulkan.level,android.hardware.vulkan.version,android.hardware.wifi,android.hardware.wifi.direct,android.software.app_widgets,android.software.autofill,android.software.backup,android.software.companion_device_setup,android.software.cts,android.software.device_admin,android.software.file_based_encryption,android.software.home_screen,android.software.input_methods,android.software.live_wallpaper,android.software.managed_users,android.software.midi,android.software.picture_in_picture,android.software.print,android.software.securely_removes_users,android.software.verified_boot,android.software.voice_recognizers,android.software.webview,com.google.android.feature.GOOGLE_BUILD,com.google.android.feature.GOOGLE_EXPERIENCE";
const COMMON_LIBS: &str = "android.ext.shared,android.test.base,android.test.mock,android.test.runner,com.android.future.usb.accessory,com.android.location.provider,com.android.media.remotedisplay,com.android.mediadrm.signer,com.google.android.gms,com.google.android.maps,javax.obex,org.apache.http.legacy";
const COMMON_GL: &str = "GL_EXT_color_buffer_float,GL_EXT_color_buffer_half_float,GL_EXT_copy_image,GL_EXT_debug_marker,GL_EXT_discard_framebuffer,GL_EXT_disjoint_timer_query,GL_EXT_geometry_shader,GL_EXT_gpu_shader5,GL_EXT_multisampled_render_to_texture,GL_EXT_primitive_bounding_box,GL_EXT_robustness,GL_EXT_sRGB,GL_EXT_shader_io_blocks,GL_EXT_tessellation_shader,GL_EXT_texture_border_clamp,GL_EXT_texture_buffer,GL_EXT_texture_cube_map_array,GL_EXT_texture_filter_anisotropic,GL_EXT_texture_format_BGRA8888,GL_EXT_texture_sRGB_decode,GL_KHR_debug,GL_KHR_texture_compression_astc_ldr,GL_OES_EGL_image,GL_OES_EGL_image_external,GL_OES_EGL_image_external_essl3,GL_OES_EGL_sync,GL_OES_compressed_ETC1_RGB8_texture,GL_OES_depth24,GL_OES_depth_texture,GL_OES_element_index_uint,GL_OES_packed_depth_stencil,GL_OES_rgb8_rgba8,GL_OES_standard_derivatives,GL_OES_texture_3D,GL_OES_texture_float,GL_OES_texture_half_float,GL_OES_texture_npot,GL_OES_vertex_array_object,GL_OES_vertex_half_float";
const COMMON_LOCALES: &str =
    "ar,de,de_DE,en,en_GB,en_US,es,es_ES,es_419,es_US,fr,fr_FR,hi,id,it,it_IT,ja,ja_JP,ko,nl,pl,pt,pt_BR,pt_PT,ru,ru_RU,tr,uk,vi,zh_CN,zh_TW";

/// Built-in generic profiles, one per primary ABI family. Values describe Android 14/11
/// reference builds; they are not tied to any person's device.
fn builtin(name: &str) -> Option<BTreeMap<String, String>> {
    let (abis, sdk, release, id, device, model, product, density, w, h) = match name {
        "arm64" => (
            "arm64-v8a,armeabi-v7a,armeabi",
            "34",
            "14",
            "UQ1A.240205.004",
            "generic_arm64",
            "Generic ARM64 Phone",
            "generic_arm64",
            "420",
            "1080",
            "2400",
        ),
        "armv7" => (
            "armeabi-v7a,armeabi",
            "30",
            "11",
            "RQ3A.211001.001",
            "generic_armv7",
            "Generic ARMv7 Phone",
            "generic_armv7",
            "320",
            "720",
            "1520",
        ),
        "x86_64" => (
            "x86_64,x86,arm64-v8a,armeabi-v7a,armeabi",
            "34",
            "14",
            "UQ1A.240205.004",
            "generic_x86_64",
            "Generic x86_64 Device",
            "generic_x86_64",
            "440",
            "1080",
            "2340",
        ),
        "x86" => (
            "x86,armeabi-v7a,armeabi",
            "30",
            "11",
            "RQ3A.211001.001",
            "generic_x86",
            "Generic x86 Device",
            "generic_x86",
            "240",
            "800",
            "1280",
        ),
        _ => return None,
    };
    let mut m = BTreeMap::new();
    let mut set = |k: &str, v: &str| {
        m.insert(k.to_string(), v.to_string());
    };
    set("UserReadableName", model);
    set("Build.BOOTLOADER", "unknown");
    set("Build.BRAND", "generic");
    set("Build.DEVICE", device);
    set(
        "Build.FINGERPRINT",
        &format!("generic/{product}/{device}:{release}/{id}/1:user/release-keys"),
    );
    set("Build.HARDWARE", "generic");
    set("Build.ID", id);
    set("Build.MANUFACTURER", "Generic");
    set("Build.MODEL", model);
    set("Build.PRODUCT", product);
    set("Build.RADIO", "unknown");
    set("Build.VERSION.RELEASE", release);
    set("Build.VERSION.SDK_INT", sdk);
    set("CellOperator", "310260");
    set("SimOperator", "310260");
    set("Roaming", "mobile-notroaming");
    set("Client", "android-google");
    set("Features", COMMON_FEATURES);
    set("GL.Extensions", COMMON_GL);
    set("GL.Version", "196610");
    set("GSF.version", "203615037");
    set("HasFiveWayNavigation", "false");
    set("HasHardKeyboard", "false");
    set("Keyboard", "1");
    set("Locales", COMMON_LOCALES);
    set("Navigation", "1");
    set("Platforms", abis);
    set("Screen.Density", density);
    set("Screen.Width", w);
    set("Screen.Height", h);
    set("ScreenLayout", "2");
    set("SharedLibraries", COMMON_LIBS);
    set("TimeZone", "UTC");
    set("TouchScreen", "3");
    set("Vending.version", "82201710");
    set("Vending.versionString", "22.0.17-21 [0] [PR] 332555730");
    Some(m)
}

pub const BUILTIN_PROFILES: [&str; 4] = ["arm64", "armv7", "x86_64", "x86"];

/// Parses a `.properties` file with `[section]` headers into profiles.
pub fn parse_properties(text: &str) -> Vec<DeviceProfile> {
    let mut out: Vec<DeviceProfile> = Vec::new();
    let mut current: Option<DeviceProfile> = None;
    for line in text.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') || l.starts_with(';') {
            continue;
        }
        if l.starts_with('[') && l.ends_with(']') {
            if let Some(p) = current.take() {
                out.push(p);
            }
            current = Some(DeviceProfile {
                name: l[1..l.len() - 1].trim().to_string(),
                props: BTreeMap::new(),
            });
            continue;
        }
        if let Some((k, v)) = l.split_once('=') {
            let p = current.get_or_insert_with(|| DeviceProfile {
                name: "default".into(),
                props: BTreeMap::new(),
            });
            p.props.insert(k.trim().to_string(), v.trim().replace("\\:", ":").replace("\\=", "="));
        }
    }
    if let Some(p) = current.take() {
        out.push(p);
    }
    out
}

impl DeviceProfile {
    pub fn builtin(name: &str) -> Option<Self> {
        builtin(name).map(|props| Self { name: name.into(), props })
    }

    fn s(&self, k: &str) -> Option<String> {
        self.props.get(k).cloned()
    }
    fn i(&self, k: &str) -> Option<i32> {
        self.props.get(k).and_then(|v| v.parse().ok())
    }
    fn b(&self, k: &str) -> Option<bool> {
        self.props.get(k).map(|v| v.eq_ignore_ascii_case("true"))
    }
    fn list(&self, k: &str) -> Vec<String> {
        self.props
            .get(k)
            .map(|v| v.split(',').map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect())
            .unwrap_or_default()
    }

    pub fn missing_keys(&self) -> Vec<&'static str> {
        const REQUIRED: [&str; 12] = [
            "Build.DEVICE",
            "Build.FINGERPRINT",
            "Build.HARDWARE",
            "Build.ID",
            "Build.MODEL",
            "Build.PRODUCT",
            "Build.VERSION.SDK_INT",
            "Build.VERSION.RELEASE",
            "Platforms",
            "Screen.Density",
            "Vending.version",
            "Vending.versionString",
        ];
        REQUIRED.into_iter().filter(|k| !self.props.contains_key(*k)).collect()
    }

    pub fn abis(&self) -> Vec<String> {
        self.list("Platforms")
    }

    pub fn sdk(&self) -> i32 {
        self.i("Build.VERSION.SDK_INT").unwrap_or(30)
    }

    pub fn build_id(&self) -> String {
        self.s("Build.ID").unwrap_or_default()
    }

    pub fn device(&self) -> String {
        self.s("Build.DEVICE").unwrap_or_default()
    }

    pub fn gsf_version(&self) -> i32 {
        self.i("GSF.version").unwrap_or(203615037)
    }

    pub fn checkin_proto(&self, now_secs: i64) -> AndroidCheckinProto {
        AndroidCheckinProto {
            build: Some(AndroidBuildProto {
                id: self.s("Build.FINGERPRINT"),
                product: self.s("Build.HARDWARE"),
                carrier: self.s("Build.BRAND"),
                radio: self.s("Build.RADIO"),
                bootloader: self.s("Build.BOOTLOADER"),
                client: self.s("Client").or(Some("android-google".into())),
                timestamp: Some(now_secs),
                google_services: Some(self.gsf_version()),
                device: self.s("Build.DEVICE"),
                sdk_version: Some(self.sdk()),
                model: self.s("Build.MODEL"),
                manufacturer: self.s("Build.MANUFACTURER"),
                build_product: self.s("Build.PRODUCT"),
                ota_installed: Some(false),
            }),
            last_checkin_msec: Some(0),
            cell_operator: self.s("CellOperator"),
            sim_operator: self.s("SimOperator"),
            roaming: self.s("Roaming"),
            user_number: Some(0),
        }
    }

    pub fn device_config(&self) -> DeviceConfigurationProto {
        let features = self.list("Features");
        DeviceConfigurationProto {
            touch_screen: self.i("TouchScreen"),
            keyboard: self.i("Keyboard"),
            navigation: self.i("Navigation"),
            screen_layout: self.i("ScreenLayout"),
            has_hard_keyboard: self.b("HasHardKeyboard"),
            has_five_way_navigation: self.b("HasFiveWayNavigation"),
            screen_density: self.i("Screen.Density"),
            gl_es_version: self.i("GL.Version"),
            system_shared_library: self.list("SharedLibraries"),
            system_available_feature: features.clone(),
            native_platform: self.list("Platforms"),
            screen_width: self.i("Screen.Width"),
            screen_height: self.i("Screen.Height"),
            system_supported_locale: self.list("Locales"),
            gl_extension: self.list("GL.Extensions"),
            device_class: Some(0),
            max_apk_download_size_mb: Some(50),
            smallest_screen_width_dp: Some(320),
            low_ram_device: Some(0),
            total_memory_bytes: Some(8_354_971_648),
            max_num_of_cpu_cores: Some(8),
            device_feature: features
                .into_iter()
                .map(|n| DeviceFeature {
                    name: Some(n),
                    value: Some(0),
                })
                .collect(),
        }
    }

    /// `User-Agent` sent to `/fdfe` endpoints (Play Store client format).
    pub fn finsky_user_agent(&self) -> String {
        format!(
            "Android-Finsky/{} (api=3,versionCode={},sdk={},device={},hardware={},product={},platformVersionRelease={},model={},buildId={},isWideScreen=0,supportedAbis={})",
            self.s("Vending.versionString").unwrap_or_default(),
            self.s("Vending.version").unwrap_or_default(),
            self.sdk(),
            self.device(),
            self.s("Build.HARDWARE").unwrap_or_default(),
            self.s("Build.PRODUCT").unwrap_or_default(),
            self.s("Build.VERSION.RELEASE").unwrap_or_default(),
            self.s("Build.MODEL").unwrap_or_default(),
            self.build_id(),
            self.abis().join(";"),
        )
    }

    pub fn auth_user_agent(&self) -> String {
        format!("GoogleAuth/1.4 ({} {})", self.device(), self.build_id())
    }

    pub fn sim_operator(&self) -> Option<String> {
        self.s("SimOperator")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtins_are_complete() {
        for n in BUILTIN_PROFILES {
            let p = DeviceProfile::builtin(n).unwrap();
            assert!(p.missing_keys().is_empty(), "{n}: {:?}", p.missing_keys());
            let cfg = p.device_config();
            assert!(!cfg.native_platform.is_empty());
            assert!(p.finsky_user_agent().starts_with("Android-Finsky/"));
        }
        assert_eq!(DeviceProfile::builtin("arm64").unwrap().abis()[0], "arm64-v8a");
    }

    #[test]
    fn parses_properties_files() {
        let t = "[pixel]\n# comment\nBuild.FINGERPRINT=google/x/y\\:14/ID/1\\:user/release-keys\nPlatforms=arm64-v8a,armeabi-v7a\n\n[tv]\nPlatforms=armeabi-v7a\n";
        let ps = parse_properties(t);
        assert_eq!(ps.len(), 2);
        assert_eq!(ps[0].props["Build.FINGERPRINT"], "google/x/y:14/ID/1:user/release-keys");
        assert_eq!(ps[1].abis(), vec!["armeabi-v7a"]);
    }
}
