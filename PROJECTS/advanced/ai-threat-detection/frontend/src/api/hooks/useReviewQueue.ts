import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import { z } from 'zod'
import { ThreatEventSchema, type ThreatEvent } from '@/api/types'
import { apiClient, QUERY_STRATEGIES } from '@/core/api'

const REVIEW_QUEUE_KEY = ['threats', 'review-queue'] as const

export function useReviewQueue() {
  return useQuery<ThreatEvent[]>({
    queryKey: REVIEW_QUEUE_KEY,
    queryFn: async () => {
      const { data } = await apiClient.get<unknown>('/threats/review-queue')
      return z.array(ThreatEventSchema).parse(data)
    },
    ...QUERY_STRATEGIES.frequent,
  })
}

export function useReviewThreat() {
  const queryClient = useQueryClient()

  return useMutation<
    ThreatEvent,
    unknown,
    { id: string; label: 'true_positive' | 'false_positive' }
  >({
    mutationFn: async ({ id, label }: { id: string; label: 'true_positive' | 'false_positive' }) => {
      const { data } = await apiClient.patch<unknown>(`/threats/${id}/review`, { label })
      return ThreatEventSchema.parse(data)
    },
    onSuccess: () => {
      toast.success('Feedback recorded')
      queryClient.invalidateQueries({ queryKey: REVIEW_QUEUE_KEY })
    },
    onError: () => {
      toast.error('Failed to record feedback')
    },
  })
}