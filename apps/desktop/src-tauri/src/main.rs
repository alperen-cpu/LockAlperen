// No console window in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    if let Some(code) = lockalperen_desktop_lib::native_host_mode() {
        std::process::exit(code);
    }
    lockalperen_desktop_lib::run();
}
