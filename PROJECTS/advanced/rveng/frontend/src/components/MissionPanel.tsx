// ===================
// © AngelaMos | 2026
// MissionPanel.tsx
// ===================

import type { ChallengeDetail } from '@/api/types'
import { CATEGORY_LABEL } from '@/config'
import { formatBytes } from '@/lib/format'
import styles from './MissionPanel.module.scss'

interface MissionPanelProps {
  challenge: ChallengeDetail
  solved: boolean
}

export function MissionPanel({
  challenge,
  solved,
}: MissionPanelProps): React.ReactElement {
  return (
    <div className={styles.panel}>
      <div className={styles.head}>
        <span className={styles.module}>{challenge.module}</span>
        {solved && <span className={styles.solved}>Solved</span>}
      </div>
      <h2 className={styles.title}>{challenge.title}</h2>
      <p className={styles.mission}>{challenge.mission}</p>
      <div className={styles.meta}>
        <span className={styles.category}>
          {CATEGORY_LABEL[challenge.category]}
        </span>
        <span className={styles.size}>{formatBytes(challenge.size)}</span>
      </div>
    </div>
  )
}
