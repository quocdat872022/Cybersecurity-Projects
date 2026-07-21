// ===================
// © AngelaMos | 2026
// SectionMap.tsx
// ===================

import type { SectionView } from '@/api/types'
import { formatAddr, formatOffset } from '@/lib/format'
import styles from './SectionMap.module.scss'

export function SectionMap({
  sections,
}: {
  sections: SectionView[]
}): React.ReactElement {
  return (
    <div className={styles.wrap}>
      <table className={styles.table}>
        <thead>
          <tr>
            <th>#</th>
            <th>Name</th>
            <th>Type</th>
            <th>Addr</th>
            <th>Offset</th>
            <th className={styles.num}>Size</th>
            <th>Flags</th>
          </tr>
        </thead>
        <tbody>
          {sections.map((section) => (
            <tr
              key={section.index}
              className={section.flags.includes('X') ? styles.exec : ''}
            >
              <td className={styles.dim}>{section.index}</td>
              <td className={styles.name}>{section.name || '(null)'}</td>
              <td>{section.type}</td>
              <td className={styles.mono}>{formatAddr(section.addr)}</td>
              <td className={styles.mono}>{formatOffset(section.offset)}</td>
              <td className={styles.num}>{section.size}</td>
              <td className={styles.flags}>{section.flags || '-'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
