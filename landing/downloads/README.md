Place the macOS installer here as:

```text
Tethra.dmg
```

`Tethra.dmg` is the canonical local artifact. The production Firebase Spark
site cannot publish macOS installer files directly, so it serves
`Tethra.dmg.zip`, which must contain that exact DMG. When `landing/index.html`
is opened with `file://`, `analytics.js` rewrites the download buttons to the
raw relative `./downloads/Tethra.dmg` target.

The current alpha is Apple Silicon only, signed with an Apple Developer ID,
notarized by Apple, and distributed in a DMG with a stapled notarization ticket.
Update `SHA256SUMS.txt` whenever either artifact changes.
