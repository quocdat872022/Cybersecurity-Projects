// ===================
// © AngelaMos | 2026
// routers.tsx
// ===================

import { createBrowserRouter } from 'react-router-dom'
import { ROUTES } from '@/config'
import { Shell } from './shell'

export const router = createBrowserRouter([
  {
    element: <Shell />,
    children: [
      {
        path: ROUTES.HOME,
        lazy: () => import('@/pages/browser'),
      },
      {
        path: ROUTES.CHALLENGE,
        lazy: () => import('@/pages/workspace'),
      },
      {
        path: '*',
        lazy: () => import('@/pages/browser'),
      },
    ],
  },
])
