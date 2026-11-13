fn main() {
    // Declare the app's own commands so that they are denied unless a
    // capability file grants them explicitly (least privilege).
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(
        tauri_build::AppManifest::new().commands(&[
            "pick_vault_file",
            "unlock",
            "lock",
            "list_entries",
        ]),
    ))
    .expect("failed to run tauri-build");
}
