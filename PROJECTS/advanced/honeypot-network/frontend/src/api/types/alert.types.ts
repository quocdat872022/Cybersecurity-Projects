import { z } from 'zod'

export const alertSchema = z.object({
  id: z.string(),
  rule: z.string(),
  severity: z.string(),
  summary: z.string(),
  triggered_at: z.string(),
  sensor_id: z.string(),
  source_ip: z.string(),
  service_type: z.string(),
  delivery: z.string(),
  attempts: z.number(),
  delivery_error: z.string().optional(),
  mitre: z
    .array(
      z.object({
        technique_id: z.string(),
        name: z.string().optional(),
        tactic: z.string().optional(),
      })
    )
    .optional(),
})

export type Alert = z.infer<typeof alertSchema>