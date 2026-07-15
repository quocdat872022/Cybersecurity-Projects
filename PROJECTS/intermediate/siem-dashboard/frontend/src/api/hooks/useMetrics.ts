// ===================
// ©AngelaMos | 2026
// useMetrics.ts
// ===================

import type { UseQueryResult } from '@tanstack/react-query'
import { useQuery } from '@tanstack/react-query'
import type {
  MetricsBucket,
  MetricsQueryParams,
  MetricsSummary,
} from '@/api/types'
import { API_ENDPOINTS, QUERY_KEYS } from '@/config'
import { apiClient, QUERY_STRATEGIES } from '@/core/lib'

export const useMetricsSummary = (
  params: MetricsQueryParams = {}
): UseQueryResult<MetricsSummary, Error> => {
  return useQuery({
    queryKey: QUERY_KEYS.METRICS.SUMMARY(params),
    queryFn: async () => {
      const response = await apiClient.get<MetricsSummary>(
        API_ENDPOINTS.METRICS.SUMMARY,
        { params }
      )
      return response.data
    },
    ...QUERY_STRATEGIES.dashboard,
  })
}

export const useMetricsTimeline = (
  params: MetricsQueryParams = {}
): UseQueryResult<MetricsBucket[], Error> => {
  return useQuery({
    queryKey: QUERY_KEYS.METRICS.TIMELINE(params),
    queryFn: async () => {
      const response = await apiClient.get<MetricsBucket[]>(
        API_ENDPOINTS.METRICS.TIMELINE,
        { params }
      )
      return response.data
    },
    ...QUERY_STRATEGIES.dashboard,
  })
}