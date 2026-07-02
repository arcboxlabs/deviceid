//! A device ID that can't be faked.
//!
//! The ID is the fingerprint of a P-256 key held by the machine's security
//! hardware (macOS Secure Enclave, Windows TPM 2.0, Linux keyring fallback).
//! Claiming the ID means signing with the key; cloning the ID means stealing
//! silicon, not copying a string.

use std::path::PathBuf;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use hardware_enclave::{AccessPolicy, BackendKind, EnclaveConfig, SignerHandle, create_signer};
use napi::Result;
use napi_derive::napi;
use p256::pkcs8::{EncodePublicKey, LineEnding};
use sha2::{Digest, Sha256};

fn crypto_err(context: &str, err: impl std::fmt::Display) -> napi::Error {
    napi::Error::from_reason(format!("{context}: {err}"))
}

#[napi(object)]
#[derive(Default)]
pub struct DeviceIdOptions {
    /// Directory where the hardware-wrapped key handle is persisted.
    /// Defaults to the platform key-storage location.
    pub dir: Option<String>,
    /// Namespace for the key in platform key storage (keychain service name
    /// on macOS). Defaults to "deviceid".
    pub app_name: Option<String>,
    /// Key label within the namespace. Defaults to "device".
    pub label: Option<String>,
}

/// This machine's identity: a keypair whose private half never leaves the
/// security hardware. Obtain via {@link ensureDeviceId}.
#[napi]
pub struct DeviceId {
    signer: SignerHandle,
    label: String,
    spki_der: Vec<u8>,
    pem: String,
}

#[napi]
impl DeviceId {
    /// The device ID: `SHA256:<base64>` fingerprint of the public key
    /// (SPKI DER), following the SSH fingerprint convention. Stable for the
    /// lifetime of the key; survives re-installs while the handle persists.
    #[napi(getter)]
    pub fn id(&self) -> String {
        format!(
            "SHA256:{}",
            STANDARD_NO_PAD.encode(Sha256::digest(&self.spki_der))
        )
    }

    /// The public key as SPKI PEM, for enrolling this device with a server.
    #[napi(getter)]
    pub fn public_key_pem(&self) -> String {
        self.pem.clone()
    }

    /// Where the private key lives. `hardware` means it cannot be extracted
    /// from this machine (Secure Enclave / TPM); `software` means it is
    /// encrypted at rest but usable if copied along with its OS keyring.
    #[napi(getter)]
    pub fn protection(&self) -> String {
        match self.signer.backend_kind() {
            BackendKind::SecureEnclave | BackendKind::Tpm | BackendKind::TpmBridge => "hardware",
            _ => "software",
        }
        .to_string()
    }

    /// Prove possession of the device key: ECDSA P-256 signature over
    /// `payload` (SHA-256 applied internally), returned as base64url-encoded
    /// P1363 (`r || s`) — verifiable with WebCrypto as-is.
    #[napi]
    pub fn sign(&self, payload: String) -> Result<String> {
        let der = self
            .signer
            .sign(&self.label, payload.as_bytes())
            .map_err(|e| crypto_err("device key signing failed", e))?;
        let sig = p256::ecdsa::Signature::from_der(&der)
            .map_err(|e| crypto_err("invalid DER signature from backend", e))?;
        Ok(URL_SAFE_NO_PAD.encode(sig.to_bytes()))
    }
}

/// Ensure this machine has a device identity: load the existing key or
/// generate one in the security hardware. Idempotent — the same installation
/// always resolves to the same key, and therefore the same {@link DeviceId#id}.
#[napi]
pub fn ensure_device_id(options: Option<DeviceIdOptions>) -> Result<DeviceId> {
    let opts = options.unwrap_or_default();
    let app_name = opts.app_name.unwrap_or_else(|| "deviceid".to_string());
    let label = opts.label.unwrap_or_else(|| "device".to_string());

    let mut config = EnclaveConfig::new(app_name, label.clone());
    // Headless-friendly: never demand Touch ID / password to sign. Without
    // this, unsigned binaries (dev builds, plain node) default to
    // AccessPolicy::Any, which prompts on every use.
    config.access_policy = Some(AccessPolicy::None);
    config.keys_dir = opts.dir.map(PathBuf::from);
    // Physical machines never silently downgrade from the TPM; VMs without
    // TPM passthrough (CI, desktop virtualization) get DPAPI software keys,
    // honestly reported via `protection`.
    #[cfg(target_os = "windows")]
    {
        config.platform =
            hardware_enclave::PlatformConfig::Windows(hardware_enclave::WindowsConfig {
                software_fallback: hardware_enclave::WindowsSoftwareFallback::VmOnly,
                ..Default::default()
            });
    }

    let signer = create_signer(&config)
        .map_err(|e| crypto_err("no usable key backend on this machine", e))?;
    if !signer
        .key_exists(&label)
        .map_err(|e| crypto_err("key lookup failed", e))?
    {
        signer
            .generate_key(&label, AccessPolicy::None)
            .map_err(|e| crypto_err("device key generation failed", e))?;
    }

    let sec1 = signer
        .public_key(&label)
        .map_err(|e| crypto_err("public key export failed", e))?;
    let public_key = p256::PublicKey::from_sec1_bytes(&sec1)
        .map_err(|e| crypto_err("backend returned an invalid P-256 point", e))?;
    let spki_der = public_key
        .to_public_key_der()
        .map_err(|e| crypto_err("SPKI encoding failed", e))?
        .into_vec();
    let pem = public_key
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| crypto_err("PEM encoding failed", e))?;

    Ok(DeviceId {
        signer,
        label,
        spki_der,
        pem,
    })
}
