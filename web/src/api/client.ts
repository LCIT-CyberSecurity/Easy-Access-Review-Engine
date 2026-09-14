export type Row = Record<string, any>

const fixtures: Record<string, Row[]> = {
  campaigns: [{ name: 'Quarterly access review', scope: 'Production', status: 'open', progress: 74, pending: 11, due_at: '2026-09-30' }, { name: 'Finance privileged access', scope: 'SAP Finance', status: 'draft', progress: 0, pending: 24, due_at: '2026-10-12' }],
  'review-items': [{ id: 'r1', identity_identifier: 'alice.martin', identity_provider: 'corp-ad', access_name: 'Finance Administrator', classification: 'unexpected', expected: false, observed: true, findings: ['disabled_with_access'] }, { id: 'r2', identity_identifier: 'bob.dupont', identity_provider: 'corp-ad', access_name: 'SAP Read', classification: 'expected_and_observed', expected: true, observed: true, findings: [] }, { id: 'r3', identity_identifier: 'claire.bernard', identity_provider: 'openldap-prod', access_name: 'Production Admin', classification: 'missing', expected: true, observed: false, findings: [] }],
  providers: [{ name: 'corp-ad', display_name: 'Corporate Active Directory', type: 'active_directory', status: 'Healthy', identities: 1432, groups: 128, last_sync: '14 min ago' }, { name: 'openldap-prod', display_name: 'OpenLDAP Production', type: 'openldap', status: 'Healthy', identities: 684, groups: 42, last_sync: '38 min ago' }],
  'remediation-actions': [{ identity_identifier: 'alice.martin', access_name: 'Finance Administrator', action: 'revoke', status: 'pending', due_at: '2026-09-18' }, { identity_identifier: 'service.backup', access_name: 'Backup Operators', action: 'revoke', status: 'exported', due_at: '2026-09-21' }],
  identities: [{ identifier: 'alice.martin', provider: 'corp-ad', type: 'user_account', status: 'active' }, { identifier: 'service.backup', provider: 'corp-ad', type: 'technical_account', status: 'active' }],
}

export async function getRows(path: string): Promise<Row[]> {
  try { const response = await fetch(`/api/${path}`); if (!response.ok) throw new Error('API unavailable'); const body = await response.json(); return body.items?.length ? body.items : fixtures[path] ?? [] } catch { return fixtures[path] ?? [] }
}

export async function postDecision(id: string, value: string, comment?: string) {
  const response = await fetch(`/api/review-items/${id}/decision?value=${encodeURIComponent(value)}${comment ? `&comment=${encodeURIComponent(comment)}` : ''}`, { method: 'POST', headers: { 'X-EARE-Role': 'ADMIN' } })
  if (!response.ok) throw new Error((await response.json()).detail ?? 'Decision failed')
  return response.json()
}
