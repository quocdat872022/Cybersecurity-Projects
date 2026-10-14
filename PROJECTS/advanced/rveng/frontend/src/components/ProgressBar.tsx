// ===================
// © AngelaMos | 2026
// ProgressBar.tsx
// ===================

import styles from './ProgressBar.module.scss'

interface ProgressBarProps {
  solved: number
  total: number
}

export function ProgressBar({
  solved,
  total,
}: ProgressBarProps): React.ReactElement {
  const pct = total > 0 ? Math.round((solved / total) * 100) : 0
  return (
    <div className={styles.wrap}>
      <div className={styles.label}>
        <span>Progress</span>
        <span>
          {solved} / {total}
        </span>
      </div>
      <div className={styles.track}>
        <div className={styles.fill} style={{ width: `${pct}%` }} />
      </div>
    </div>
  )
}
