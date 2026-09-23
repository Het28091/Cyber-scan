# Dashboard accessibility acceptance

Reviewed 2026-09-23 on commit `2931acccf97640f1edd2fa894449b1277e229131`.
[CI run 35816620962](https://github.com/Het28091/Cyber-scan/actions/runs/35816620962)
passed all eleven jobs. [Machine-readable results](evidence/v1-accessibility.json)
record the tested views and unresolved automated-check classifications.

## Completed checks

- Real Chromium with axe-core 4.10.3, WCAG 2 A/AA and 2.1 AA rule tags:
  zero reported violations in five dashboard views, two dialogs and mobile overview.
- Keyboard opening/closing of the assessment dialog and restoration of focus;
  finding dialog dismissal, accessible dialog names and visible focus styling.
- Desktop 1440-pixel and mobile 390-pixel screenshots reviewed; no page-width overflow.
- Increased supporting text sizes and strengthened contrast for labels, badges,
  reports, coverage notes and status messages. Mobile headings/actions wrap.

## Manual review of automated incomplete results

Axe marked some symbol glyphs, gradient-backed text and offscreen mobile navigation
as incomplete for contrast; these are preserved in the results, not counted as passes.
Source-color checks and screenshot review found:

- Refresh/close symbols: `#6f7d90` on white, 4.19:1 (above the 3:1 non-text threshold).
  These controls have accessible names independent of their glyphs.
- Navigation symbols: 6.21:1 inactive and 6.84:1 active against their backgrounds.
- Stat symbols: 5.61:1; gradient-panel heading/supporting text: at least 13.73:1/5.56:1
  against its darker background endpoint.
- Mobile navigation intentionally scrolls horizontally within its own row; it does
  not widen the page. Offscreen navigation entries are not all visible simultaneously.

## Limits

This is bounded acceptance of existing dashboard workflows, not a WCAG certification.
A screen-reader user study, every zoom/viewport combination, all operating-system font
renderings and a comprehensive assistive-technology matrix have not been tested.
