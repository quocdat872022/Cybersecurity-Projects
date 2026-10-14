// ===================
// © AngelaMos | 2026
// client.ts
// ===================

import { API_ENDPOINTS } from '@/config'
import { apiClient } from '@/core/api'
import type {
  CfgView,
  ChallengeDetail,
  ChallengeSummary,
  DisasmView,
  ElfView,
  HexView,
  ProgressView,
  StringsView,
  SubmitRequest,
  SubmitResult,
  Target,
  XrefsView,
} from './types'

export async function fetchChallenges(): Promise<ChallengeSummary[]> {
  const { data } = await apiClient.get<ChallengeSummary[]>(
    API_ENDPOINTS.CHALLENGES
  )
  return data
}

export async function fetchChallenge(cid: string): Promise<ChallengeDetail> {
  const { data } = await apiClient.get<ChallengeDetail>(
    API_ENDPOINTS.CHALLENGE(cid)
  )
  return data
}

export async function fetchHex(
  cid: string,
  offset: number,
  length: number
): Promise<HexView> {
  const { data } = await apiClient.get<HexView>(API_ENDPOINTS.HEX(cid), {
    params: { offset, length },
  })
  return data
}

export async function fetchElf(cid: string): Promise<ElfView> {
  const { data } = await apiClient.get<ElfView>(API_ENDPOINTS.ELF(cid))
  return data
}

export async function fetchDisasm(
  cid: string,
  target: Target,
  session: string
): Promise<DisasmView> {
  const { data } = await apiClient.get<DisasmView>(API_ENDPOINTS.DISASM(cid), {
    params: { symbol: target.symbol, address: target.address, session },
  })
  return data
}

export async function fetchCfg(cid: string, target: Target): Promise<CfgView> {
  const { data } = await apiClient.get<CfgView>(API_ENDPOINTS.CFG(cid), {
    params: { symbol: target.symbol, address: target.address },
  })
  return data
}

export async function fetchXrefs(
  cid: string,
  target: number
): Promise<XrefsView> {
  const { data } = await apiClient.get<XrefsView>(API_ENDPOINTS.XREFS(cid), {
    params: { target },
  })
  return data
}

export async function fetchStrings(
  cid: string,
  minLength: number
): Promise<StringsView> {
  const { data } = await apiClient.get<StringsView>(API_ENDPOINTS.STRINGS(cid), {
    params: { min_length: minLength },
  })
  return data
}

export async function fetchProgress(session: string): Promise<ProgressView> {
  const { data } = await apiClient.get<ProgressView>(API_ENDPOINTS.PROGRESS, {
    params: { session },
  })
  return data
}

export async function submitAnswer(
  cid: string,
  body: SubmitRequest
): Promise<SubmitResult> {
  const { data } = await apiClient.post<SubmitResult>(
    API_ENDPOINTS.SUBMIT(cid),
    body
  )
  return data
}
