export const MAX_UPLOAD_BYTES = 200 * 1024 * 1024

export const UPLOAD_ERRORS = {
  unsupported: 'Unsupported file type. Upload a .pcap or .pcapng trace.',
  empty: 'The file is empty.',
  tooLarge: 'File exceeds the 200 MB limit.',
} as const

const SUPPORTED_EXTENSIONS = ['.pcap', '.pcapng']

/** Returns the rejection message for an invalid file, or `null` when the file is acceptable. */
export function validateUploadSync(file: Pick<File, 'name' | 'size'>): string | null {
  const lower = file.name.toLowerCase()
  const supported = SUPPORTED_EXTENSIONS.some((ext) => lower.endsWith(ext))
  if (!supported) return UPLOAD_ERRORS.unsupported
  if (file.size === 0) return UPLOAD_ERRORS.empty
  if (file.size > MAX_UPLOAD_BYTES) return UPLOAD_ERRORS.tooLarge
  return null
}

/** Rejects with a specific message when the upload is not acceptable (spec 8.2). */
export async function validateUpload(file: Pick<File, 'name' | 'size'>): Promise<void> {
  const message = validateUploadSync(file)
  if (message) throw new Error(message)
}

export function isSupportedExtension(fileName: string): boolean {
  const lower = fileName.toLowerCase()
  return SUPPORTED_EXTENSIONS.some((ext) => lower.endsWith(ext))
}
