import { describe, expect, it } from 'vitest'
import { currentStateLabels } from './projections'

describe('currentStateLabels', () => {
  it('renders observed and expected independently', () => {
    expect(currentStateLabels(true, true)).toEqual(['Observed ✓', 'Expected ✓'])
    expect(currentStateLabels(true, false)).toEqual(['Observed ✓', 'Expected Not expected'])
  })
})
