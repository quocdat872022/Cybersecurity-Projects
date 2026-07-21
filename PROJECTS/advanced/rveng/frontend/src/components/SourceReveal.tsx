// ===================
// © AngelaMos | 2026
// SourceReveal.tsx
// ===================

import styles from './SourceReveal.module.scss'

export function SourceReveal({ source }: { source: string }): React.ReactElement {
  return (
    <div className={styles.reveal}>
      <h3 className={styles.heading}>Source revealed</h3>
      <p className={styles.note}>
        You reached the answer from the binary. Here is the C that produced it.
      </p>
      <pre className={styles.code}>{source}</pre>
    </div>
  )
}
