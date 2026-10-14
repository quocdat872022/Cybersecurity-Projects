// ===================
// © AngelaMos | 2026
// config.ts
// ===================

export const API_ENDPOINTS = {
  CHALLENGES: '/challenges',
  CHALLENGE: (cid: string) => `/challenges/${cid}`,
  HEX: (cid: string) => `/challenges/${cid}/hex`,
  ELF: (cid: string) => `/challenges/${cid}/elf`,
  DISASM: (cid: string) => `/challenges/${cid}/disasm`,
  CFG: (cid: string) => `/challenges/${cid}/cfg`,
  XREFS: (cid: string) => `/challenges/${cid}/xrefs`,
  STRINGS: (cid: string) => `/challenges/${cid}/strings`,
  SUBMIT: (cid: string) => `/challenges/${cid}/submit`,
  PROGRESS: '/progress',
} as const

export const QUERY_KEYS = {
  CHALLENGES: ['challenges'] as const,
  CHALLENGE: (cid: string) => ['challenges', cid] as const,
  HEX: (cid: string, offset: number, length: number) =>
    ['challenges', cid, 'hex', offset, length] as const,
  ELF: (cid: string) => ['challenges', cid, 'elf'] as const,
  DISASM: (cid: string, label: string, session: string) =>
    ['challenges', cid, 'disasm', label, session] as const,
  CFG: (cid: string, label: string) => ['challenges', cid, 'cfg', label] as const,
  XREFS: (cid: string, target: number) =>
    ['challenges', cid, 'xrefs', target] as const,
  STRINGS: (cid: string, minLength: number) =>
    ['challenges', cid, 'strings', minLength] as const,
  PROGRESS: (session: string) => ['progress', session] as const,
} as const

export const ROUTES = {
  HOME: '/',
  CHALLENGE: '/c/:cid',
  challenge: (cid: string) => `/c/${cid}`,
} as const

export const STORAGE_KEYS = {
  UI: 'rveng-ui',
  SESSION: 'rveng-session',
} as const

export const CATEGORY = {
  FOUND_VALUE: 'found_value',
  IDENTIFIED_SYMBOL: 'identified_symbol',
  PATCHED_BYTES: 'patched_bytes',
} as const

export type Category = (typeof CATEGORY)[keyof typeof CATEGORY]

export const CATEGORY_LABEL: Record<Category, string> = {
  [CATEGORY.FOUND_VALUE]: 'Find a value',
  [CATEGORY.IDENTIFIED_SYMBOL]: 'Name a symbol',
  [CATEGORY.PATCHED_BYTES]: 'Patch bytes',
}

export const CATEGORY_HINT: Record<Category, string> = {
  [CATEGORY.FOUND_VALUE]: 'Submit the value in decimal or hex (0x...)',
  [CATEGORY.IDENTIFIED_SYMBOL]: 'Submit the exact symbol name',
  [CATEGORY.PATCHED_BYTES]: 'Submit the replacement bytes as hex (e.g. 9090)',
}

export const HEX = {
  DEFAULT_LENGTH: 256,
  PAGE_LENGTH: 256,
  MAX_LENGTH: 4096,
  BYTES_PER_LINE: 16,
} as const

export const STRINGS = {
  DEFAULT_MIN_LENGTH: 4,
  MIN_MIN_LENGTH: 1,
  MAX_MIN_LENGTH: 64,
} as const

export const QUERY_CONFIG = {
  STALE_TIME: {
    STATIC: Number.POSITIVE_INFINITY,
    DEFAULT: 1000 * 60 * 5,
    FREQUENT: 1000 * 30,
  },
  GC_TIME: {
    DEFAULT: 1000 * 60 * 30,
    LONG: 1000 * 60 * 60,
  },
  RETRY: {
    DEFAULT: 2,
    NONE: 0,
  },
} as const

export const HTTP_STATUS = {
  OK: 200,
  BAD_REQUEST: 400,
  NOT_FOUND: 404,
  PAYLOAD_TOO_LARGE: 413,
  UNPROCESSABLE: 422,
  INTERNAL_SERVER: 500,
} as const
