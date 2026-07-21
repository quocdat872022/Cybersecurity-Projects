// ===================
// © AngelaMos | 2026
// index.ts
// ===================

import type { Category } from '@/config'

export interface ChallengeSummary {
  id: string
  module: string
  title: string
}

export interface ChallengeDetail {
  id: string
  module: string
  title: string
  mission: string
  category: Category
  size: number
}

export interface HexView {
  base: number
  length: number
  lines: string[]
}

export interface FunctionView {
  name: string
  value: number
  size: number
}

export interface DiscoveredFunction {
  address: number
  label: string
}

export interface SectionView {
  index: number
  name: string
  type: string
  addr: number
  offset: number
  size: number
  flags: string
}

export interface ElfView {
  type: number
  machine: number
  entry: number
  sections: SectionView[]
  functions: FunctionView[]
  discovered: DiscoveredFunction[]
}

export interface InstructionView {
  address: number
  mnemonic: string
  op_str: string
  bytes: string
  immediate: number | null
  branch_target: number | null
  rip_target: number | null
  call_name: string | null
  is_gate: boolean
}

export interface DisasmView {
  symbol: string
  instructions: InstructionView[]
  gate_address: number | null
}

export interface CfgBlock {
  start: number
  end: number
  instructions: number[]
}

export interface CfgEdge {
  src: number
  dst: number
  kind: string
}

export interface CfgView {
  symbol: string
  blocks: CfgBlock[]
  edges: CfgEdge[]
}

export interface XrefView {
  from_addr: number
  to_addr: number
  kind: string
}

export interface XrefsView {
  target: number
  references: XrefView[]
}

export interface Target {
  label: string
  address: number
  symbol?: string
}

export interface StringView {
  offset: number
  text: string
}

export interface StringsView {
  strings: StringView[]
}

export interface SubmitRequest {
  answer: string
  session: string
}

export interface SubmitResult {
  correct: boolean
  message: string
  revealed_source: string | null
}

export interface ProgressView {
  session: string
  solved: string[]
  total: number
}
