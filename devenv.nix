{ ... }:

{
  # Rust toolchain (rustc, cargo, clippy, rustfmt, rust-analyzer) is
  # project-scoped via devenv; nothing is installed globally. The macOS
  # Swift bridge in hardware-enclave resolves swiftc/SDK itself through
  # the system /usr/bin/xcrun, so Xcode CLT is the only host requirement.
  languages.rust.enable = true;

  # Use the host Xcode CLT SDK instead of the nixpkgs apple-sdk: the Swift
  # bridge is compiled by the system swiftc (via /usr/bin/xcrun), and mixing
  # it with the pinned nix SDK fails ("SDK is not supported by the compiler").
  apple.sdk = null;
}
