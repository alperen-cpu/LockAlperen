fn main() {
    // Declare the app's own commands so that they are denied unless a
    // capability file grants them explicitly (least privilege).
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(
        tauri_build::AppManifest::new().commands(&[
            "pick_vault_file",
            "unlock",
            "lock",
            "list_entries",
            "copy_field",
            "reveal_password",
            "lock_status",
            "pick_new_vault_path",
            "create_vault",
            "recent_vaults",
            "select_recent",
            "forget_recent",
            "list_groups",
            "entry_form",
            "save_entry",
            "delete_entry",
            "generate_password",
            "totp_code",
            "password_health",
            "pick_kdbx_file",
            "import_kdbx",
        ]),
    ))
    .expect("failed to run tauri-build");
}
