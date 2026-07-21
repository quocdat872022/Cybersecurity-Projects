// ===================
// © AngelaMos | 2026
// index.tsx
// ===================

import { useChallenges, useProgress } from '@/api/hooks'
import { ChallengeCard, ProgressBar } from '@/components'
import styles from './browser.module.scss'

export function Component(): React.ReactElement {
  const challenges = useChallenges()
  const progress = useProgress()
  const solvedSet = new Set(progress.data?.solved ?? [])

  return (
    <div className={styles.page}>
      <header className={styles.header}>
        <h1 className={styles.title}>Challenges</h1>
        <p className={styles.subtitle}>
          Read the binary. Reach the answer. Reveal the source.
        </p>
      </header>

      {progress.data && (
        <div className={styles.progress}>
          <ProgressBar
            solved={progress.data.solved.length}
            total={progress.data.total}
          />
        </div>
      )}

      {challenges.isLoading && <p className={styles.state}>Loading...</p>}
      {challenges.isError && (
        <p className={styles.state}>Failed to load challenges</p>
      )}

      {challenges.data && (
        <div className={styles.grid}>
          {challenges.data.map((challenge) => (
            <ChallengeCard
              key={challenge.id}
              challenge={challenge}
              solved={solvedSet.has(challenge.id)}
            />
          ))}
        </div>
      )}
    </div>
  )
}

Component.displayName = 'Browser'
