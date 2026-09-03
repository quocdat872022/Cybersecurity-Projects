import { useReviewQueue, useReviewThreat } from '@/api/hooks/useReviewQueue'
import { MethodBadge } from '@/components'
import styles from './review.module.scss'

export function Component(): React.ReactElement {
  const { data: items, isLoading } = useReviewQueue()
  const review = useReviewThreat()

  if (isLoading) {
    return <div className={styles.loading}>Loading review queue...</div>
  }

  if (!items || items.length === 0) {
    return <div className={styles.empty}>No MEDIUM-severity events awaiting review.</div>
  }

  return (
    <div className={styles.page}>
      <h1 className={styles.title}>Review Queue</h1>
      <p className={styles.subtitle}>
        Unreviewed MEDIUM-severity events — labeling these improves the next retrain.
      </p>

      <div className={styles.list}>
        {items.map((threat) => (
          <div key={threat.id} className={styles.card}>
            <div className={styles.cardHeader}>
              <MethodBadge method={threat.request_method} />
              <span className={styles.path}>{threat.request_path}</span>
              <span className={styles.score}>{threat.threat_score.toFixed(3)}</span>
            </div>
            <div className={styles.meta}>
              <span>{threat.source_ip}</span>
              {threat.matched_rules && threat.matched_rules.length > 0 && (
                <span>{threat.matched_rules.join(', ')}</span>
              )}
            </div>
            <div className={styles.actions}>
              <button
                type="button"
                className={styles.truePositive}
                disabled={review.isPending}
                onClick={() => review.mutate({ id: threat.id, label: 'true_positive' })}
              >
                True Positive
              </button>
              <button
                type="button"
                className={styles.falsePositive}
                disabled={review.isPending}
                onClick={() => review.mutate({ id: threat.id, label: 'false_positive' })}
              >
                False Positive
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

Component.displayName = 'ReviewQueuePage'