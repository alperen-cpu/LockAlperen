// Typed wrappers for the four Rust commands. These are the WebView's ONLY
// capabilities (see src-tauri/capabilities/main.json).
import { invoke } from "@tauri-apps/api/core";

export interface VaultInfo {
  name: string;
  entryCount: number;
}

/** Shown on the unlock screen. KDF values are as declared by the (not yet
 *  authenticated) header: display only. */
export interface SelectedFile {
  fileName: string;
  folder: string;
  kdf: { memoryMib: number; iterations: number; parallelism: number } | null;
  keyfileRequired: boolean;
}

// Deliberately no password, notes, TOTP or custom fields: Rust never sends them.
export interface EntrySummary {
  id: string;
  title: string;
  username: string;
  url: string;
  groupId: string;
  group: string;
}

/** Opens the native file picker. Returns null if the user cancelled. */
export const pickVaultFile = () => invoke<SelectedFile | null>("pick_vault_file");

export const unlock = (password: string) => invoke<VaultInfo>("unlock", { password });

export const lock = () => invoke<void>("lock");

export const listEntries = () => invoke<EntrySummary[]>("list_entries");

/** Rust returns user-facing strings; anything else is shown generically. */
export function errorText(e: unknown): string {
  return typeof e === "string" ? e : "Beklenmeyen bir hata oluştu.";
}
