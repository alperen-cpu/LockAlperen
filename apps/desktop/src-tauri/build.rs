/// Linux: builds nodump/nodump.c into a shared library that the bundle
/// carries as a resource (tauri.linux.conf.json). It must exist before
/// tauri-build copies the resources.
fn build_nodump() {
    println!("cargo:rerun-if-changed=nodump/nodump.c");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        return;
    }
    let root = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let dir = root.join("target").join("nodump");
    std::fs::create_dir_all(&dir).expect("target/nodump");
    let status = cc::Build::new()
        .get_compiler()
        .to_command()
        .args(["-shared", "-fPIC", "-O2", "-Wall", "-Wextra", "-Werror"])
        .args(["-Wl,-z,relro,-z,now", "-o"])
        .arg(dir.join("liblav_nodump.so"))
        .arg(root.join("nodump").join("nodump.c"))
        .status()
        .expect("C compiler for nodump.c");
    assert!(status.success(), "nodump.c did not compile");
}

fn main() {
    build_nodump();
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
            "duplicate_entry",
            "generate_password",
            "totp_code",
            "password_health",
            "pick_kdbx_file",
            "import_kdbx",
            "pick_keyfile",
            "clear_keyfile",
            "entry_extras",
            "reveal_extra",
            "copy_extra",
            "save_attachment",
            "get_settings",
            "set_settings",
            "add_group",
            "rename_group",
            "delete_group",
            "empty_recycle_bin",
            "search_hidden",
            "get_gen_profiles",
            "set_gen_profiles",
            "vault_settings",
            "set_vault_settings",
            "clear_history",
            "change_kdf",
            "pick_new_keyfile",
            "change_keyfile",
            "pick_merge_file",
            "pick_merge_keyfile",
            "merge_vault",
            "export_kdbx",
            "export_html",
            "list_tabs",
            "new_tab",
            "switch_tab",
            "close_tab",
            "tab_state",
            "gdrive_status",
            "gdrive_set_client",
            "gdrive_connect",
            "gdrive_disconnect",
            "gdrive_set_auto",
            "gdrive_backup_now",
            "gdrive_list",
            "gdrive_restore",
            "restore_version",
            "add_attachment",
            "remove_attachment",
            "change_master",
            "export_csv",
            "pick_import_keyfile",
            "fetch_icons",
            "auto_type",
            "open_url",
            "move_group",
            "move_entry",
            "set_group_icon",
            "set_titlebar",
            "hotkey_active",
            "app_version",
            "check_update",
            "install_update",
            "bridge_status",
            "bridge_set_enabled",
            "bridge_revoke",
        ]),
    ))
    .expect("failed to run tauri-build");
}
