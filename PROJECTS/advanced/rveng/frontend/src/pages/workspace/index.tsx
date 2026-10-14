// ===================
// © AngelaMos | 2026
// index.tsx
// ===================

import { Link, useParams } from 'react-router-dom'
import { Workspace } from '@/components'
import { ROUTES } from '@/config'
import styles from './workspace.module.scss'

export function Component(): React.ReactElement {
  const { cid } = useParams<{ cid: string }>()

  if (!cid) {
    return <div className={styles.page}>No challenge selected</div>
  }

  return (
    <div className={styles.page}>
      <Link to={ROUTES.HOME} className={styles.back}>
        Back to challenges
      </Link>
      <Workspace cid={cid} />
    </div>
  )
}

Component.displayName = 'ChallengeWorkspace'
