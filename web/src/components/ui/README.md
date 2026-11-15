# Aurora UI foundation

These primitives are the shared starting point for future UI work. Existing pages
and workflows intentionally keep their current markup and styles in this phase.

- `Button` supports primary, secondary, outline, subtle, destructive and link variants; `asChild` uses Radix Slot.
- `Input` and `Label` wrap native form elements with Aurora token-based utility styles.
- `Separator` uses Radix Separator for semantic orientation and decorative behavior.
- `cn` joins conditional classes and resolves conflicting Tailwind utilities.

Tailwind utilities are available through `src/styles/tailwind.css`. Aurora's
existing `src/styles.css` is loaded in the `legacy` layer. Do not add Tailwind
Preflight or replace Aurora tokens, theme attributes, or user appearance preferences.
