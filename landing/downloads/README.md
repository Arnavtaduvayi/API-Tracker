Place the macOS installer here as:

```text
Tethra.dmg
```

`Tethra.dmg` is the canonical source-linked artifact committed with the site.
Firebase Spark rejects installer binaries at upload time, so production links
directly to the notarized `.dmg` and Windows `.exe` assets on GitHub Releases.
There is no ZIP wrapper. `scripts/verify_landing_release.sh` compares the
public macOS asset to this file before Firebase can deploy the landing page.

The current alpha is Apple Silicon only, signed with an Apple Developer ID,
notarized by Apple, and distributed in a DMG with a stapled notarization ticket.
Update `SHA256SUMS.txt` whenever either platform artifact changes.
