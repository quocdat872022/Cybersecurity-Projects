// ===================
// ©AngelaMos | 2026
// index.tsx
//
// Performance metrics page: p50/p95/p99 by endpoint with slowdown alerts
// ===================

import { curveMonotoneX } from '@visx/curve'
import { ParentSize } from '@visx/responsive'
import {
  AnimatedAreaSeries,
  AnimatedAxis,
  AnimatedGrid,
  AnimatedLineSeries,
  Tooltip,
  XYChart,
} from '@visx/xychart'
import { LuTriangleAlert } from 'react-icons/lu'
import { useMetricsSummary, useMetricsTimeline } from '@/api/hooks'
import type { EndpointMetric, MetricsBucket } from '@/api/types'
import { chartTheme } from '@/core/charts'
import styles from './metrics.module.scss'

const xAccessor = (d: MetricsBucket) => new Date(d.bucket)
const p50Accessor = (d: MetricsBucket) => d.p50 ?? 0
const p95Accessor = (d: MetricsBucket) => d.p95 ?? 0

export function Component(): React.ReactElement {
  const { data: summary, isLoading: summaryLoading } = useMetricsSummary({
    hours: 1,
    baseline_hours: 24,
  })
  const { data: timeline, isLoading: timelineLoading } = useMetricsTimeline({
    hours: 6,
  })

  return (
    <div className={styles.page}>
      {summary?.any_slowdown && (
        <div className={styles.alertBanner}>
          <LuTriangleAlert />
          One or more endpoints are slower than their historical baseline
        </div>
      )}

      <div className={styles.panel}>
        <h3 className={styles.title}>Response Time (p50 / p95, last 6h)</h3>
        {timelineLoading || !timeline || timeline.length === 0 ? (
          <div className={styles.skeleton} />
        ) : (
          <div className={styles.chart}>
            <ParentSize>
              {({ width }) => (
                <XYChart
                  height={280}
                  width={width}
                  xScale={{ type: 'time' }}
                  yScale={{ type: 'linear' }}
                  theme={chartTheme}
                >
                  <AnimatedGrid columns={false} numTicks={4} />
                  <AnimatedAxis orientation="bottom" numTicks={6} />
                  <AnimatedAxis orientation="left" numTicks={4} />
                  <AnimatedAreaSeries
                    dataKey="p50 (ms)"
                    data={timeline}
                    xAccessor={xAccessor}
                    yAccessor={p50Accessor}
                    fillOpacity={0.12}
                    curve={curveMonotoneX}
                  />
                  <AnimatedLineSeries
                    dataKey="p95 (ms)"
                    data={timeline}
                    xAccessor={xAccessor}
                    yAccessor={p95Accessor}
                    curve={curveMonotoneX}
                  />
                  <Tooltip
                    snapTooltipToDatumX
                    showVerticalCrosshair
                    renderTooltip={({ tooltipData }) => {
                      const datum = tooltipData?.nearestDatum?.datum as
                        | MetricsBucket
                        | undefined
                      if (!datum) return null
                      return (
                        <div>
                          <div>{new Date(datum.bucket).toLocaleTimeString()}</div>
                          <div>p50: {datum.p50?.toFixed(0)}ms</div>
                          <div>p95: {datum.p95?.toFixed(0)}ms</div>
                        </div>
                      )
                    }}
                  />
                </XYChart>
              )}
            </ParentSize>
          </div>
        )}
      </div>

      <div className={styles.grid}>
        {summaryLoading ? (
          Array.from({ length: 4 }, (_, i) => (
            <div key={`skel-${i}`} className={styles.cardSkeleton} />
          ))
        ) : summary?.endpoints.length === 0 ? (
          <div className={styles.empty}>No timing samples yet</div>
        ) : (
          summary?.endpoints.map((m) => <EndpointCard key={m.endpoint} metric={m} />)
        )}
      </div>
    </div>
  )
}

Component.displayName = 'Metrics'

function EndpointCard({ metric }: { metric: EndpointMetric }): React.ReactElement {
  return (
    <div
      className={`${styles.card} ${metric.slowdown_alert ? styles.cardAlert : ''}`}
    >
      <div className={styles.cardHeader}>
        <span className={styles.endpoint}>{metric.endpoint}</span>
        {metric.slowdown_alert && (
          <span className={styles.alertBadge}>
            <LuTriangleAlert /> Slowdown
          </span>
        )}
      </div>
      <div className={styles.statRow}>
        <Stat label="p50" value={metric.recent.p50} />
        <Stat label="p95" value={metric.recent.p95} />
        <Stat label="p99" value={metric.recent.p99} />
      </div>
      <div className={styles.baselineNote}>
        baseline p50: {metric.baseline.p50?.toFixed(0) ?? '—'}ms · {metric.recent.count} samples
      </div>
    </div>
  )
}

function Stat({
  label,
  value,
}: {
  label: string
  value: number | null
}): React.ReactElement {
  return (
    <div className={styles.stat}>
      <span className={styles.statValue}>
        {value !== null ? `${value.toFixed(0)}ms` : '—'}
      </span>
      <span className={styles.statLabel}>{label}</span>
    </div>
  )
}