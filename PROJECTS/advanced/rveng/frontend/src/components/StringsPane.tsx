// ===================
// © AngelaMos | 2026
// StringsPane.tsx
// ===================

import { useState } from 'react'
import { useStrings } from '@/api/hooks'
import { STRINGS } from '@/config'
import { formatOffset } from '@/lib/format'
import styles from './StringsPane.module.scss'

export function StringsPane({ cid }: { cid: string }): React.ReactElement {
  const [minLength, setMinLength] = useState<number>(STRINGS.DEFAULT_MIN_LENGTH)
  const { data, isLoading, isError } = useStrings(cid, minLength)

  return (
    <div className={styles.strings}>
      <div className={styles.toolbar}>
        <label className={styles.control}>
          <span>Min length: {minLength}</span>
          <input
            type="range"
            min={STRINGS.MIN_MIN_LENGTH}
            max={STRINGS.MAX_MIN_LENGTH}
            value={minLength}
            onChange={(e) => setMinLength(Number(e.target.value))}
          />
        </label>
        {data && (
          <span className={styles.count}>{data.strings.length} strings</span>
        )}
      </div>

      {isLoading && <div className={styles.state}>Loading strings...</div>}
      {isError && <div className={styles.state}>Failed to load strings</div>}

      {data && (
        <div className={styles.list}>
          {data.strings.map((entry) => (
            <div className={styles.row} key={`${entry.offset}-${entry.text}`}>
              <span className={styles.offset}>{formatOffset(entry.offset)}</span>
              <span className={styles.text}>{entry.text}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
