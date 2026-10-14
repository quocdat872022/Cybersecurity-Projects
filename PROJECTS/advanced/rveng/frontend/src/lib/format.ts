// ===================
// © AngelaMos | 2026
// format.ts
// ===================

export function toHex(value: number, pad = 0): string {
  const body = value.toString(16).padStart(pad, '0')
  return `0x${body}`
}

export function formatAddr(value: number): string {
  return toHex(value, 6)
}

export function formatOffset(value: number): string {
  return toHex(value, 8)
}

const ELF_TYPES: Record<number, string> = {
  0: 'NONE',
  1: 'REL',
  2: 'EXEC',
  3: 'DYN',
  4: 'CORE',
}

const ELF_MACHINES: Record<number, string> = {
  3: 'x86',
  40: 'ARM',
  62: 'x86-64',
  183: 'AArch64',
  243: 'RISC-V',
}

export function elfTypeName(value: number): string {
  return ELF_TYPES[value] ?? toHex(value)
}

export function elfMachineName(value: number): string {
  return ELF_MACHINES[value] ?? toHex(value)
}

export function formatBytes(count: number): string {
  if (count < 1024) {
    return `${count} B`
  }
  return `${(count / 1024).toFixed(1)} KiB`
}
