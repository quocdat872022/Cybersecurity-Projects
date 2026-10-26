import type { UseQueryResult } from '@tanstack/react-query'
import { useQuery } from '@tanstack/react-query'
import type { Alert, ApiResponse } from '@/api/types'
import { API_ENDPOINTS, QUERY_KEYS } from '@/config'
import { apiClient, QUERY_STRATEGIES } from '@/core/api'

export const useAlerts = (limit = 10): UseQueryResult<Alert[], Error> => {
  return useQuery({
    queryKey: QUERY_KEYS.ALERTS.LIST(limit),
    queryFn: async () => {
      const response = await apiClient.get<ApiResponse<Alert[]>>(
        API_ENDPOINTS.ALERTS.LIST,
        { params: { limit } }
      )
      return response.data.data
    },
    ...QUERY_STRATEGIES.live,
  })
}