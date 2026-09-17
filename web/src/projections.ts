export function currentStateLabels(observed: boolean, expected: boolean): string[] {
  return ['Observed ' + (observed ? '✓' : 'Not observed'), 'Expected ' + (expected ? '✓' : 'Not expected')]
}

export function pageCount(total: number, limit: number): number { return Math.max(1, Math.ceil(total / Math.max(1, limit))) }
export function pageLabel(total: number, limit: number, offset: number): string {
  if (!total) return 'Showing 0–0 of 0'
  return `Showing ${offset + 1}–${Math.min(offset + limit, total)} of ${total}`
}
export function roleHome(role: string): string {
  if (role === 'GROUP_OWNER') return '/reviews'
  if (role === 'BUSINESS_ADMIN') return '/actions'
  return '/'
}
export function campaignCtas(status: string, pending: number): string[] {
  if (status === 'draft') return ['open', 'cancel']
  if (status === 'open') return pending ? ['close-disabled'] : ['close']
  if (status === 'closed') return ['promote', 'report']
  return []
}
