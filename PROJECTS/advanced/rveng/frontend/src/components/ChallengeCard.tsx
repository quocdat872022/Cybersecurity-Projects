// ===================
// © AngelaMos | 2026
// ChallengeCard.tsx
// ===================

import { Link } from 'react-router-dom'
import type { ChallengeSummary } from '@/api/types'
import { ROUTES } from '@/config'
import styles from './ChallengeCard.module.scss'

interface ChallengeCardProps {
  challenge: ChallengeSummary
  solved: boolean
}

export function ChallengeCard({
  challenge,
  solved,
}: ChallengeCardProps): React.ReactElement {
  return (
    <Link to={ROUTES.challenge(challenge.id)} className={styles.card}>
      <div className={styles.top}>
        <span className={styles.module}>{challenge.module}</span>
        {solved && <span className={styles.solved}>Solved</span>}
      </div>
      <h3 className={styles.title}>{challenge.title}</h3>
      <span className={styles.id}>{challenge.id}</span>
    </Link>
  )
}
