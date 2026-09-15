export function currentStateLabels(observed: boolean, expected: boolean): string[] {
  return [
    'Observed ' + (observed ? '✓' : 'Not observed'),
    'Expected ' + (expected ? '✓' : 'Not expected'),
  ]
}
