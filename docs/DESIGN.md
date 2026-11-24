# Design system: civic paper ledger

SecureVote's UI is intentionally unlike a generic startup dashboard. It is
modelled on election paperwork: a poll card, a marked ballot sheet, a private
receipt, a sealed envelope and a certified return. That gives every screen a
recognisable physical metaphor and avoids the "purple gradient + rounded cards"
look common in generated interfaces.

## Principles

1. **Paper first.** Warm off-white backgrounds, ink-coloured type and fine
   ruled lines. Shadows are hard offset stamps, not blurred glows.
2. **One loud accent.** Vermilion is reserved for the stamp, current step,
   primary action and result bars. Everything else is ink, paper or muted olive.
3. **Editorial type.** Display headings use the user's system serif stack;
   labels and records use monospace small caps. No web fonts are downloaded.
4. **Records, not widgets.** Statistics, audit entries and ballot commitments
   are laid out as ledger rows with tabular numerals and explicit borders.
5. **State is visible.** A persistent status strip shows the election title and
   open/closed state; a four-step progress ledger appears on every voting page.
6. **No hidden machinery.** No JavaScript, no inline styles, no external
   assets, no icon fonts. The CSP remains `script-src 'none'`.

## Tokens

| Token | Value | Use |
| --- | --- | --- |
| `--paper` | `#f4efe4` | Page background |
| `--card` | `#fffdf7` | Ballot sheets, cards, poll card |
| `--ink` / `--navy` | `#1d252b` / `#18252c` | Body text / masthead and table headers |
| `--accent` | `#a63a2a` | Stamp, primary action, current step, result bars |
| `--line` / `--line-strong` | `#d9cfbc` / `#b9ad96` | Hairlines and double rules |
| `--ok` / `--danger` / `--warn` | `#2f6b4f` / `#a32b1c` / `#8a5a16` | Status notices and badges |
| `--serif` | Iowan / Palatino / Georgia | Headings, ballot labels, receipt values |
| `--mono` | System monospace | Tracking codes, hashes, labels, metadata |

All tokens live in [`secure_vote/static/style.css`](../secure_vote/static/style.css).
The CSS is the single source of visual truth; `views.py` supplies semantic
classes only.

## Screen grammar

| Screen | Physical metaphor | Required cues |
| --- | --- | --- |
| Overview | Poll card + election notice | `The civic ledger`, election name, live status card, at-a-glance ledger, three numbered steps, scope note |
| Sign in / register | Roll book | Form index, explicit labels, hints, demo accounts as a tear-off notice |
| Ballot | Official ballot sheet | Dark masthead, lettered options, final-choice warning beside the cast button |
| Receipt | Private paper receipt | Dashed border, `Save now` stamp, tabular fields, print hint, one-click verify |
| Verify | Public notice board | Two evidence types, ruled bulletin-board table, empty ledger state |
| Results (open) | Sealed envelope | `Sealed` stamp, no partial numbers, links to verify/audit meanwhile |
| Results (closed) | Certified return | Digest masthead, flat result bars, integrity checks, JSON download |
| Audit | Bound ledger | Chain-status notice, ruled event table, full JSON download |
| Admin | Control sheet | State badge, irreversible-action danger zone, live statistics |

## Interaction rules

- Every POST keeps a synchronizer CSRF token; the UI never relies on JS to
  submit, validate or copy values.
- Forms use real `<label for>`, `autocomplete`, hints and visible focus rings.
- Ballot options are large enough for touch; option letters are decorative and
  `aria-hidden`, while the radio remains the accessible control.
- `<progress>` is used for results so no inline width styles are needed; each
  bar keeps an `aria-label`.
- Native `<details>`/CSS is preferred over scripted disclosure if future
  components are added.
- `@media print` hides navigation and actions so the receipt can be saved as a
  clean PDF from the browser.

## Anti-patterns

Do **not** add:

- purple/blue mesh gradients, glassmorphism, neon glows or blurred hero blobs;
- external fonts, CDN CSS, remote images, icon libraries or tracking pixels;
- JavaScript for basic form behaviour, inline `style=""` attributes, or
  `unsafe-inline` CSP exceptions;
- a second accent colour, emoji status icons, or decorative illustrations that
  compete with ballot data;
- generic "cards everywhere" layouts where a ruled ledger/table is clearer.

## Change checklist

- [ ] Run `make check` and `make check-all`.
- [ ] Regenerate `screenshots/` with `/tmp/shot/capture.mjs` or the browser E2E.
- [ ] Verify keyboard focus, skip link, unique IDs and `aria-current`.
- [ ] Check the receipt in print preview.
- [ ] Confirm no new external request appears in the network panel.
- [ ] Update this document and `CHANGELOG.md` for any visual-system change.
