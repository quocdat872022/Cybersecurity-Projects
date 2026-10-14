// ===================
// © AngelaMos | 2026
// index.ts
// ===================

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { QUERY_KEYS } from '@/config'
import { QUERY_STRATEGIES } from '@/core/api'
import { getSessionId } from '@/lib/session'
import {
  fetchCfg,
  fetchChallenge,
  fetchChallenges,
  fetchDisasm,
  fetchElf,
  fetchHex,
  fetchProgress,
  fetchStrings,
  fetchXrefs,
  submitAnswer,
} from '../client'
import type { SubmitResult, Target } from '../types'

export function useChallenges() {
  return useQuery({
    queryKey: QUERY_KEYS.CHALLENGES,
    queryFn: fetchChallenges,
    ...QUERY_STRATEGIES.static,
  })
}

export function useChallenge(cid: string) {
  return useQuery({
    queryKey: QUERY_KEYS.CHALLENGE(cid),
    queryFn: () => fetchChallenge(cid),
    enabled: cid.length > 0,
    ...QUERY_STRATEGIES.static,
  })
}

export function useHex(cid: string, offset: number, length: number) {
  return useQuery({
    queryKey: QUERY_KEYS.HEX(cid, offset, length),
    queryFn: () => fetchHex(cid, offset, length),
    enabled: cid.length > 0,
    ...QUERY_STRATEGIES.static,
  })
}

export function useElf(cid: string) {
  return useQuery({
    queryKey: QUERY_KEYS.ELF(cid),
    queryFn: () => fetchElf(cid),
    enabled: cid.length > 0,
    ...QUERY_STRATEGIES.static,
  })
}

export function useDisasm(cid: string, target: Target | null) {
  const session = getSessionId()
  return useQuery({
    queryKey: QUERY_KEYS.DISASM(cid, target?.label ?? '', session),
    queryFn: () => fetchDisasm(cid, target as Target, session),
    enabled: cid.length > 0 && target !== null,
    ...QUERY_STRATEGIES.standard,
  })
}

export function useCfg(cid: string, target: Target | null) {
  return useQuery({
    queryKey: QUERY_KEYS.CFG(cid, target?.label ?? ''),
    queryFn: () => fetchCfg(cid, target as Target),
    enabled: cid.length > 0 && target !== null,
    ...QUERY_STRATEGIES.static,
  })
}

export function useXrefs(cid: string, target: number | null) {
  return useQuery({
    queryKey: QUERY_KEYS.XREFS(cid, target ?? -1),
    queryFn: () => fetchXrefs(cid, target as number),
    enabled: cid.length > 0 && target !== null,
    ...QUERY_STRATEGIES.static,
  })
}

export function useStrings(cid: string, minLength: number) {
  return useQuery({
    queryKey: QUERY_KEYS.STRINGS(cid, minLength),
    queryFn: () => fetchStrings(cid, minLength),
    enabled: cid.length > 0,
    ...QUERY_STRATEGIES.static,
  })
}

export function useProgress() {
  const session = getSessionId()
  return useQuery({
    queryKey: QUERY_KEYS.PROGRESS(session),
    queryFn: () => fetchProgress(session),
    ...QUERY_STRATEGIES.standard,
  })
}

export function useSubmit(cid: string) {
  const queryClient = useQueryClient()
  const session = getSessionId()
  return useMutation<SubmitResult, Error, string>({
    mutationFn: (answer: string) => submitAnswer(cid, { answer, session }),
    onSuccess: (result) => {
      if (result.correct) {
        queryClient.invalidateQueries({ queryKey: QUERY_KEYS.PROGRESS(session) })
        queryClient.invalidateQueries({
          queryKey: ['challenges', cid, 'disasm'],
        })
      }
    },
  })
}
