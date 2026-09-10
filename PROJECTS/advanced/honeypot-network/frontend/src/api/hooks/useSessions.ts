// ===================
// ©AngelaMos | 2026
// useSessions.ts
// ===================

import type { UseQueryResult } from '@tanstack/react-query'
import { useQuery } from '@tanstack/react-query'
import type { ApiResponse, PaginatedResponse, Session } from '@/api/types'
import { API_ENDPOINTS, PAGINATION, QUERY_KEYS } from '@/config'
import { apiClient, QUERY_STRATEGIES } from '@/core/api'

export const sessionQueries = {
  all: () => QUERY_KEYS.SESSIONS.ALL,
  list: (limit: number, offset: number, service?: string, minScore?: number) =>
    [...QUERY_KEYS.SESSIONS.LIST(limit, offset, service), { minScore }] as const,
  byId: (id: string) => QUERY_KEYS.SESSIONS.BY_ID(id),
  replay: (id: string) => QUERY_KEYS.SESSIONS.REPLAY(id),
} as const

export const useSessions = (
  limit = PAGINATION.DEFAULT_LIMIT,
  offset = 0,
  service?: string,
  minScore?: number
): UseQueryResult<PaginatedResponse<Session[]>, Error> => {
  return useQuery({
    queryKey: sessionQueries.list(limit, offset, service, minScore),
    queryFn: async () => {
      const response = await apiClient.get<PaginatedResponse<Session[]>>(
        API_ENDPOINTS.SESSIONS.LIST,
        { params: { limit, offset, service, min_score: minScore } }
      )
      return response.data
    },
    ...QUERY_STRATEGIES.standard,
  })
}

export const useSession = (id: string): UseQueryResult<Session, Error> => {
  return useQuery({
    queryKey: sessionQueries.byId(id),
    queryFn: async () => {
      const response = await apiClient.get<ApiResponse<Session>>(
        API_ENDPOINTS.SESSIONS.BY_ID(id)
      )
      return response.data.data
    },
    enabled: id.length > 0,
  })
}

export const useSessionReplay = (id: string): UseQueryResult<string, Error> => {
  return useQuery({
    queryKey: sessionQueries.replay(id),
    queryFn: async () => {
      const response = await apiClient.get<string>(
        API_ENDPOINTS.SESSIONS.REPLAY(id),
        { responseType: 'text' }
      )
      return response.data
    },
    enabled: id.length > 0,
  })
}
