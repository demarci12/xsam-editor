// Saving and opening files. Uses the File System Access API (Chrome, Edge, the Claude app) so a
// file opened from disk can be saved back in place; other browsers fall back to downloads.

type Kind = 'xsam' | 'project'

const TYPES: Record<Kind, { description: string; accept: Record<string, string[]> }> = {
  xsam: { description: 'XSAM model (MPS export)', accept: { 'application/xml': ['.xsam'] } },
  project: { description: 'TARA project', accept: { 'application/json': ['.json'] } },
}

/** Minimal typing of the parts of the File System Access API used here. */
interface FsHandle {
  name: string
  kind: 'file'
  getFile(): Promise<File>
  createWritable(): Promise<{ write(data: string): Promise<void>; close(): Promise<void> }>
  queryPermission?(o: { mode: 'readwrite' }): Promise<PermissionState>
  requestPermission?(o: { mode: 'readwrite' }): Promise<PermissionState>
}
export type FileHandle = FsHandle

interface FsWindow {
  showOpenFilePicker(o: object): Promise<FsHandle[]>
  showSaveFilePicker(o: object): Promise<FsHandle>
}
const fsWindow = () => window as unknown as Partial<FsWindow>

export const canSaveInPlace = () => typeof fsWindow().showSaveFilePicker === 'function' && typeof fsWindow().showOpenFilePicker === 'function'

/** The user closed the picker: not an error. */
export const isAbort = (e: unknown) => e instanceof DOMException && e.name === 'AbortError'

export async function pickFileToOpen(): Promise<{ handle: FsHandle; name: string; text: string } | null> {
  const [handle] = await fsWindow().showOpenFilePicker!({
    types: [
      { description: 'XSAM model or TARA project', accept: { 'application/xml': ['.xsam', '.xml'], 'application/json': ['.json'] } },
    ],
    excludeAcceptAllOption: false,
    multiple: false,
  })
  const file = await handle.getFile()
  return { handle, name: file.name, text: await file.text() }
}

export async function pickFileToSave(kind: Kind, suggestedName: string): Promise<FsHandle> {
  return fsWindow().showSaveFilePicker!({ suggestedName, types: [TYPES[kind]] })
}

/** Write text to a file handle, asking for write permission when needed. */
export async function writeFile(handle: FsHandle, text: string): Promise<void> {
  if (handle.queryPermission && (await handle.queryPermission({ mode: 'readwrite' })) !== 'granted') {
    if (!handle.requestPermission || (await handle.requestPermission({ mode: 'readwrite' })) !== 'granted') throw new Error(`No permission to write ${handle.name}`)
  }
  const w = await handle.createWritable()
  await w.write(text)
  await w.close()
}

export function download(name: string, text: string, type: string) {
  const a = document.createElement('a')
  a.href = URL.createObjectURL(new Blob([text], { type }))
  a.download = name
  a.click()
  setTimeout(() => URL.revokeObjectURL(a.href), 1000)
}
