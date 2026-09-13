import { describe, expect, it, vi } from 'vitest'
import { getRows, postDecision } from './client'

describe('API client', () => {
  it('falls back to isolated fixtures when the API is unavailable', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('offline')))

    await expect(getRows('campaigns')).resolves.toEqual([
      expect.objectContaining({ name: 'Quarterly access review' }),
      expect.objectContaining({ name: 'Finance privileged access' }),
    ])
  })

  it('posts a decision through the REST API', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ id: 'decision-1' }),
    })
    vi.stubGlobal('fetch', fetchMock)

    await expect(postDecision('review-1', 'approve', 'Reviewed')).resolves.toEqual({ id: 'decision-1' })
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/review-items/review-1/decision?value=approve&comment=Reviewed',
      expect.objectContaining({ method: 'POST' }),
    )
  })
})
