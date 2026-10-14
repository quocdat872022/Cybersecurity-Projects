// ===================
// © AngelaMos | 2026
// AnswerRunner.tsx
// ===================

import { type FormEvent, useState } from 'react'
import { useSubmit } from '@/api/hooks'
import type { SubmitResult } from '@/api/types'
import { CATEGORY_HINT, type Category } from '@/config'
import styles from './AnswerRunner.module.scss'
import { SourceReveal } from './SourceReveal'

interface AnswerRunnerProps {
  cid: string
  category: Category
  solved: boolean
}

export function AnswerRunner({
  cid,
  category,
  solved,
}: AnswerRunnerProps): React.ReactElement {
  const [answer, setAnswer] = useState('')
  const [result, setResult] = useState<SubmitResult | null>(null)
  const submit = useSubmit(cid)

  const onSubmit = (event: FormEvent): void => {
    event.preventDefault()
    if (answer.trim().length === 0) {
      return
    }
    submit.mutate(answer, { onSuccess: (data) => setResult(data) })
  }

  const pending = submit.isPending
  const empty = answer.trim().length === 0

  return (
    <form className={styles.runner} onSubmit={onSubmit}>
      <label className={styles.field}>
        <span className={styles.hint}>{CATEGORY_HINT[category]}</span>
        <div className={styles.inputRow}>
          <input
            className={styles.input}
            value={answer}
            onChange={(e) => setAnswer(e.target.value)}
            placeholder="Your answer"
            spellCheck={false}
            autoComplete="off"
          />
          <button type="submit" disabled={pending || empty}>
            {pending ? 'Checking...' : 'Submit'}
          </button>
        </div>
      </label>

      {result && (
        <div className={result.correct ? styles.correct : styles.incorrect}>
          {result.message}
        </div>
      )}

      {result?.correct && result.revealed_source && (
        <SourceReveal source={result.revealed_source} />
      )}

      {solved && result === null && (
        <p className={styles.solvedNote}>
          Already solved. Submit again to reveal the source.
        </p>
      )}
    </form>
  )
}
