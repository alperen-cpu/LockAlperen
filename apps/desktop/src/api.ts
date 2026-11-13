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
  hasTotp: boolean;
}

/** Opens the native file picker. Returns null if the user cancelled. */
export const pickVaultFile = () => invoke<SelectedFile | null>("pick_vault_file");

export const unlock = (password: string) => invoke<VaultInfo>("unlock", { password });

export const lock = () => invoke<void>("lock");

export const listEntries = () => invoke<EntrySummary[]>("list_entries");

export type CopyField = "username" | "password" | "totp";

/** Rust copies the value itself; it never comes to the WebView. Returns the
 *  seconds until the clipboard is cleared. */
export const copyField = (id: string, field: CopyField) =>
  invoke<number>("copy_field", { id, field });

/** Only on an explicit "show" click; the UI hides it again soon. */
export const revealPassword = (id: string) => invoke<string>("reveal_password", { id });

export interface LockStatus {
  unlocked: boolean;
  lockInSecs: number;
}

/** Rust decides when to lock (idle, Windows lock, sleep); the UI only polls. */
export const lockStatus = () => invoke<LockStatus>("lock_status");

/** Save dialog for a new vault. Returns the file name, or null. */
export const pickNewVaultPath = () => invoke<string | null>("pick_new_vault_path");

/** Creates, saves and opens the new vault. Never overwrites a file. */
export const createVault = (name: string, password: string, confirm: string) =>
  invoke<{ file: SelectedFile; info: VaultInfo }>("create_vault", { name, password, confirm });

export interface RecentVault {
  fileName: string;
  folder: string;
  /** Unix seconds. */
  opened: number;
}

export const recentVaults = () => invoke<RecentVault[]>("recent_vaults");

/** Chooses by position; Rust holds the paths. */
export const selectRecent = (index: number) => invoke<SelectedFile>("select_recent", { index });

export const forgetRecent = (index: number) => invoke<RecentVault[]>("forget_recent", { index });

export interface GroupView {
  id: string;
  name: string;
}

/** Holds secrets while the editor is open. */
export interface EntryForm {
  id: string | null;
  groupId: string;
  title: string;
  username: string;
  password: string;
  url: string;
  notes: string;
  tags: string[];
  /** Base32 secret or otpauth:// URI; "" = none. */
  totp: string;
}

export interface GenOptions {
  length: number;
  lowercase: boolean;
  uppercase: boolean;
  digits: boolean;
  symbols: boolean;
  excludeAmbiguous: boolean;
}

export const listGroups = () => invoke<GroupView[]>("list_groups");

/** Sends the entry's secrets: only when the editor opens. */
export const entryForm = (id: string) => invoke<EntryForm>("entry_form", { id });

/** Saves to disk; nothing changes on screen if the save fails. */
export const saveEntry = (form: EntryForm) =>
  invoke<{ id: string; entries: EntrySummary[] }>("save_entry", { form });

export const deleteEntry = (id: string) => invoke<EntrySummary[]>("delete_entry", { id });

export const generatePassword = (options: GenOptions) =>
  invoke<string>("generate_password", { options });

export interface TotpCode {
  code: string;
  secondsLeft: number;
  period: number;
}

/** Current code only; the TOTP secret never leaves Rust here. */
export const totpCode = (id: string) => invoke<TotpCode>("totp_code", { id });

/** Rust returns user-facing strings; anything else is shown generically. */
export function errorText(e: unknown): string {
  return typeof e === "string" ? e : "Beklenmeyen bir hata oluştu.";
}
