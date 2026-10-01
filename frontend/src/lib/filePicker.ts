/**
 * Single shared `<input type="file">` registry so the header button, the empty
 * state and the `u` hotkey all open the same picker (spec 4.2 / 4.6).
 */
let picker: HTMLInputElement | null = null

export function registerFileInput(element: HTMLInputElement | null): void {
  picker = element
}

export function openFilePicker(): void {
  picker?.click()
}

export function isFilePickerRegistered(): boolean {
  return picker !== null
}

/** Test helper: drop the registration between test cases. */
export function resetFilePicker(): void {
  picker = null
}
