/**
 * ©AngelaMos | 2026
 * shell.tsx
 */

import { Suspense } from 'react'
import { ErrorBoundary } from 'react-error-boundary'
import { Link, Outlet } from 'react-router-dom'
import { ROUTES } from '@/config'
import styles from './shell.module.scss'

function ShellErrorFallback({ error }: { error: Error }): React.ReactElement {
  return (
    <div className={styles.error}>
      <h2>Something went wrong</h2>
      <pre>{error.message}</pre>
    </div>
  )
}

function ShellLoading(): React.ReactElement {
  return <div className={styles.loading}>Loading...</div>
}

export function Shell(): React.ReactElement {
  return (
    <div className={styles.shell}>
      <header className={styles.header}>
        <Link to={ROUTES.HOME} className={styles.brand}>
          rveng
        </Link>
        <span className={styles.tag}>reverse-engineering lab</span>
      </header>

      <main className={styles.content}>
        <ErrorBoundary FallbackComponent={ShellErrorFallback}>
          <Suspense fallback={<ShellLoading />}>
            <Outlet />
          </Suspense>
        </ErrorBoundary>
      </main>
    </div>
  )
}
