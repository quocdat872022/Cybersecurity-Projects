// ===================
// © AngelaMos | 2026
// DisasmPane.tsx
// ===================

import { useMemo, useRef } from 'react'
import { useDisasm, useXrefs } from '@/api/hooks'
import type { Target } from '@/api/types'
import { formatAddr } from '@/lib/format'
import styles from './DisasmPane.module.scss'

interface DisasmPaneProps {
  cid: string
  target: Target | null
}

export function DisasmPane({ cid, target }: DisasmPaneProps): React.ReactElement {
  const { data, isLoading, isError } = useDisasm(cid, target)
  const xrefs = useXrefs(cid, target?.address ?? null)
  const rowRefs = useRef<Map<number, HTMLDivElement | null>>(new Map())

  const addresses = useMemo(
    () => new Set((data?.instructions ?? []).map((i) => i.address)),
    [data]
  )

  if (target === null) {
    return <div className={styles.state}>No function selected</div>
  }

  const scrollTo = (address: number): void => {
    rowRefs.current.get(address)?.scrollIntoView({
      block: 'center',
      behavior: 'smooth',
    })
  }

  const callers = (xrefs.data?.references ?? []).filter((r) => r.kind === 'call')

  return (
    <div className={styles.disasm}>
      <div className={styles.toolbar}>
        {data?.gate_address != null && (
          <button
            type="button"
            className={styles.gateBanner}
            onClick={() => scrollTo(data.gate_address as number)}
          >
            Gate at {formatAddr(data.gate_address)}
          </button>
        )}
        {callers.length > 0 && (
          <span className={styles.callers}>
            called by {callers.map((c) => formatAddr(c.from_addr)).join(', ')}
          </span>
        )}
      </div>

      {isLoading && <div className={styles.state}>Disassembling...</div>}
      {isError && <div className={styles.state}>Failed to disassemble</div>}

      {data && (
        <div className={styles.listing}>
          {data.instructions.map((ins) => {
            const linkable =
              ins.branch_target != null && addresses.has(ins.branch_target)
            return (
              <div
                key={ins.address}
                ref={(el) => {
                  rowRefs.current.set(ins.address, el)
                }}
                className={`${styles.row} ${ins.is_gate ? styles.gate : ''}`}
              >
                <span className={styles.addr}>{formatAddr(ins.address)}</span>
                <span className={styles.raw}>{ins.bytes}</span>
                <span className={styles.mnemonic}>{ins.mnemonic}</span>
                <span className={styles.ops}>
                  {ins.op_str}
                  {ins.call_name && (
                    <span className={styles.callName}>
                      {' '}
                      &lt;{ins.call_name}&gt;
                    </span>
                  )}
                  {ins.rip_target != null && (
                    <span className={styles.dataRef}>
                      {' '}
                      # {formatAddr(ins.rip_target)}
                    </span>
                  )}
                </span>
                {ins.branch_target != null && (
                  <button
                    type="button"
                    className={`${styles.target} ${linkable ? styles.linkable : ''}`}
                    onClick={() =>
                      linkable && scrollTo(ins.branch_target as number)
                    }
                    disabled={!linkable}
                  >
                    to {formatAddr(ins.branch_target)}
                  </button>
                )}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
