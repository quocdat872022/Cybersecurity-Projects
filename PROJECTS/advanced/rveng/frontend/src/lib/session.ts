// ===================
// © AngelaMos | 2026
// session.ts
// ===================

import { STORAGE_KEYS } from '@/config'

function createId(): string {
  if (typeof crypto !== 'undefined' && 'randomUUID' in crypto) {
    return crypto.randomUUID()
  }
  return `s-${Math.random().toString(36).slice(2)}-${Date.now().toString(36)}`
}

let cached: string | null = null

export function getSessionId(): string {
  if (cached !== null) {
    return cached
  }
  try {
    const existing = localStorage.getItem(STORAGE_KEYS.SESSION)
    if (existing) {
      cached = existing
      return existing
    }
    const fresh = createId()
    localStorage.setItem(STORAGE_KEYS.SESSION, fresh)
    cached = fresh
    return fresh
  } catch {
    cached = createId()
    return cached
  }
}
