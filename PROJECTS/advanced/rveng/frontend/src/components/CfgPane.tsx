// ===================
// © AngelaMos | 2026
// CfgPane.tsx
// ===================

import { useMemo } from 'react'
import { useCfg } from '@/api/hooks'
import type { Target } from '@/api/types'
import { formatAddr } from '@/lib/format'
import styles from './CfgPane.module.scss'

interface CfgPaneProps {
  cid: string
  target: Target | null
}

export function CfgPane({ cid, target }: CfgPaneProps): React.ReactElement {
  const { data, isLoading, isError } = useCfg(cid, target)

  const outEdges = useMemo(() => {
    const map = new Map<number, { dst: number; kind: string }[]>()
    for (const edge of data?.edges ?? []) {
      const list = map.get(edge.src) ?? []
      list.push({ dst: edge.dst, kind: edge.kind })
      map.set(edge.src, list)
    }
    return map
  }, [data])

  if (target === null) {
    return <div className={styles.state}>No function selected</div>
  }
  if (isLoading) {
    return <div className={styles.state}>Building graph...</div>
  }
  if (isError || !data) {
    return <div className={styles.state}>Failed to build graph</div>
  }

  return (
    <div className={styles.cfg}>
      <p className={styles.summary}>
        {data.blocks.length} basic blocks, {data.edges.length} edges
      </p>
      <div className={styles.blocks}>
        {data.blocks.map((block, index) => {
          const edges = outEdges.get(block.start) ?? []
          return (
            <div className={styles.block} key={block.start}>
              <div className={styles.blockHead}>
                <span className={styles.blockName}>block {index}</span>
                <span className={styles.blockRange}>
                  {formatAddr(block.start)} .. {formatAddr(block.end)}
                </span>
              </div>
              <div className={styles.blockBody}>
                {block.instructions.length} instructions
              </div>
              <div className={styles.edgeRow}>
                {edges.length === 0 ? (
                  <span className={styles.terminal}>terminal</span>
                ) : (
                  edges.map((edge) => (
                    <span
                      className={`${styles.edge} ${styles[edge.kind] ?? ''}`}
                      key={`${block.start}-${edge.dst}-${edge.kind}`}
                    >
                      {edge.kind} to {formatAddr(edge.dst)}
                    </span>
                  ))
                )}
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
