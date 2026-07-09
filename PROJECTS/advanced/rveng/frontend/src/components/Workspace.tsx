// ===================
// © AngelaMos | 2026
// Workspace.tsx
// ===================

import { useMemo, useState } from 'react'
import { useChallenge, useElf, useProgress } from '@/api/hooks'
import type { Target } from '@/api/types'
import { AnswerRunner } from './AnswerRunner'
import { CfgPane } from './CfgPane'
import { DisasmPane } from './DisasmPane'
import { HexViewer } from './HexViewer'
import { MissionPanel } from './MissionPanel'
import { SectionMap } from './SectionMap'
import { StringsPane } from './StringsPane'
import styles from './Workspace.module.scss'

const TABS = ['hex', 'disasm', 'graph', 'sections', 'strings'] as const
type Tab = (typeof TABS)[number]

const TAB_LABEL: Record<Tab, string> = {
  hex: 'Hex',
  disasm: 'Disassembly',
  graph: 'Graph',
  sections: 'Sections',
  strings: 'Strings',
}

const PREFERRED = ['check', 'main', '_start']

function pickDefault(targets: Target[]): Target | null {
  for (const name of PREFERRED) {
    const hit = targets.find((t) => t.label === name)
    if (hit) {
      return hit
    }
  }
  return targets[0] ?? null
}

export function Workspace({ cid }: { cid: string }): React.ReactElement {
  const [tab, setTab] = useState<Tab>('hex')
  const [targetKey, setTargetKey] = useState('')
  const challenge = useChallenge(cid)
  const elf = useElf(cid)
  const progress = useProgress()

  const targets = useMemo<Target[]>(() => {
    const named = (elf.data?.functions ?? [])
      .filter((f) => f.size > 0 && f.value > 0)
      .map((f) => ({ label: f.name, address: f.value, symbol: f.name }))
    if (named.length > 0) {
      return named
    }
    return (elf.data?.discovered ?? []).map((d) => ({
      label: d.label,
      address: d.address,
    }))
  }, [elf.data])

  if (challenge.isLoading) {
    return <div className={styles.state}>Loading challenge...</div>
  }
  if (challenge.isError || !challenge.data) {
    return <div className={styles.state}>Challenge not found</div>
  }

  const detail = challenge.data
  const solved = progress.data?.solved.includes(cid) ?? false
  const selected =
    targets.find((t) => t.label === targetKey) ?? pickDefault(targets)
  const needsTarget = tab === 'disasm' || tab === 'graph'

  return (
    <div className={styles.workspace}>
      <aside className={styles.side}>
        <MissionPanel challenge={detail} solved={solved} />
        <div className={styles.runnerCard}>
          <h3 className={styles.runnerTitle}>Submit answer</h3>
          <AnswerRunner cid={cid} category={detail.category} solved={solved} />
        </div>
      </aside>

      <section className={styles.analysis}>
        <div className={styles.tabs}>
          {TABS.map((item) => (
            <button
              key={item}
              type="button"
              className={`${styles.tab} ${tab === item ? styles.activeTab : ''}`}
              onClick={() => setTab(item)}
            >
              {TAB_LABEL[item]}
            </button>
          ))}
        </div>

        {needsTarget && targets.length > 0 && (
          <label className={styles.picker}>
            <span>Function</span>
            <select
              value={selected?.label ?? ''}
              onChange={(e) => setTargetKey(e.target.value)}
            >
              {targets.map((t) => (
                <option key={t.label} value={t.label}>
                  {t.label}
                </option>
              ))}
            </select>
          </label>
        )}

        <div className={styles.pane}>
          {tab === 'hex' && <HexViewer cid={cid} size={detail.size} />}
          {tab === 'disasm' &&
            (elf.isLoading ? (
              <div className={styles.state}>Loading ELF...</div>
            ) : (
              <DisasmPane cid={cid} target={selected} />
            ))}
          {tab === 'graph' &&
            (elf.isLoading ? (
              <div className={styles.state}>Loading ELF...</div>
            ) : (
              <CfgPane cid={cid} target={selected} />
            ))}
          {tab === 'sections' &&
            (elf.isLoading ? (
              <div className={styles.state}>Loading ELF...</div>
            ) : (
              <SectionMap sections={elf.data?.sections ?? []} />
            ))}
          {tab === 'strings' && <StringsPane cid={cid} />}
        </div>
      </section>
    </div>
  )
}
