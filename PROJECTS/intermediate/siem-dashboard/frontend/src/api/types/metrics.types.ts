// ===================
// ©AngelaMos | 2026
// metrics.types.ts
// ===================

import { z } from 'zod'

export const percentileStatsSchema = z.object({
  count: z.number(),
  p50: z.number().nullable(),
  p95: z.number().nullable(),
  p99: z.number().nullable(),
  min: z.number().nullable(),
  max: z.number().nullable(),
  mean: z.number().nullable(),
})

export const endpointMetricSchema = z.object({
  endpoint: z.string(),
  recent: percentileStatsSchema,
  baseline: percentileStatsSchema,
  slowdown_alert: z.boolean(),
})

export const metricsSummarySchema = z.object({
  window_hours: z.number(),
  baseline_hours: z.number(),
  endpoints: z.array(endpointMetricSchema),
  any_slowdown: z.boolean(),
})

export const metricsBucketSchema = z.object({
  bucket: z.string(),
  count: z.number(),
  p50: z.number().nullable(),
  p95: z.number().nullable(),
  mean: z.number().nullable(),
})

export type PercentileStats = z.infer<typeof percentileStatsSchema>
export type EndpointMetric = z.infer<typeof endpointMetricSchema>
export type MetricsSummary = z.infer<typeof metricsSummarySchema>
export type MetricsBucket = z.infer<typeof metricsBucketSchema>

export interface MetricsQueryParams {
  endpoint?: string
  hours?: number
  baseline_hours?: number
}