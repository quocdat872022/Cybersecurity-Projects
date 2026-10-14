// ===================
// © AngelaMos | 2026
// HexViewer.tsx
// ===================

import { type FormEvent, useState } from 'react'
import { useHex } from '@/api/hooks'
import { HEX } from '@/config'
import { formatOffset } from '@/lib/format'
import styles from './HexViewer.module.scss'

interface HexRow {
  offset: string
  bytes: string
  ascii: string
  raw: string
}

const LINE_RE = /^([0-9a-f]{8}) {2}(.+?) {2}\|(.*)\|$/

function parseLine(line: string): HexRow {
  const match = LINE_RE.exec(line)
  if (match === null) {
    return { offset: '', bytes: '', ascii: '', raw: line }
  }
  return { offset: match[1], bytes: match[2], ascii: match[3], raw: line }
}

function parseTarget(text: string): number | null {
  const token = text.trim().toLowerCase()
  if (token.length === 0) {
    return null
  }
  const value = token.startsWith('0x')
    ? Number.parseInt(token.slice(2), 16)
    : Number.parseInt(token, 10)
  return Number.isNaN(value) || value < 0 ? null : value
}

interface HexViewerProps {
  cid: string
  size: number
}

export function HexViewer({ cid, size }: HexViewerProps): React.ReactElement {
  const [offset, setOffset] = useState(0)
  const [jump, setJump] = useState('')
  const length = HEX.PAGE_LENGTH
  const { data, isLoading, isError } = useHex(cid, offset, length)

  const canPrev = offset > 0
  const canNext = offset + length < size

  const gotoPrev = (): void => setOffset(Math.max(0, offset - length))
  const gotoNext = (): void => {
    if (canNext) {
      setOffset(offset + length)
    }
  }

  const onJump = (event: FormEvent): void => {
    event.preventDefault()
    const target = parseTarget(jump)
    if (target === null) {
      return
    }
    const aligned = Math.min(target, Math.max(0, size - 1))
    setOffset(aligned - (aligned % HEX.BYTES_PER_LINE))
  }

  return (
    <div className={styles.hex}>
      <div className={styles.toolbar}>
        <div className={styles.pager}>
          <button type="button" onClick={gotoPrev} disabled={!canPrev}>
            Prev
          </button>
          <button type="button" onClick={gotoNext} disabled={!canNext}>
            Next
          </button>
        </div>
        <span className={styles.range}>
          {data
            ? `${formatOffset(data.base)} .. ${formatOffset(data.base + data.length)}`
            : formatOffset(offset)}
          <span className={styles.total}> of {size} bytes</span>
        </span>
        <form className={styles.jump} onSubmit={onJump}>
          <input
            type="text"
            value={jump}
            onChange={(e) => setJump(e.target.value)}
            placeholder="offset e.g. 0x2000"
            aria-label="Jump to offset"
          />
          <button type="submit">Go</button>
        </form>
      </div>

      {isLoading && <div className={styles.state}>Loading hex...</div>}
      {isError && <div className={styles.state}>Failed to load hex</div>}

      {data && (
        <div className={styles.dump}>
          {data.lines.map(parseLine).map((row) => (
            <div className={styles.row} key={row.offset || row.raw}>
              {row.offset ? (
                <>
                  <span className={styles.gutter}>{row.offset}</span>
                  <span className={styles.bytes}>{row.bytes}</span>
                  <span className={styles.ascii}>{row.ascii}</span>
                </>
              ) : (
                <span className={styles.bytes}>{row.raw}</span>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
