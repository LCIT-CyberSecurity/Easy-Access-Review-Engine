import { describe, expect, it, vi } from 'vitest'
import { getRows, postDecision } from './client'

describe('API client', () => {
  it('does not fabricate data when the API is unavailable', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('offline')))

    await expect(getRows('campaigns')).rejects.toThrow('offline')
  })

  it('posts a decision through the REST API', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ id: 'decision-1' }),
    })
    vi.stubGlobal('fetch', fetchMock)

    await expect(postDecision('review-1', 'approve', 'Reviewed')).resolves.toEqual({ id: 'decision-1' })
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/review-items/review-1/decision',
      expect.objectContaining({ method: 'POST', body: JSON.stringify({ value: 'approve', comment: 'Reviewed' }) }),
    )
  })
})
