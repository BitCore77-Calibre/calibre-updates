# calibre-updates

Signed public files that CALIBRE apps download: the release list (`releases.json`),
later the wallet settings and the white-label partner files. No code, no secrets.

- Format and rules: `calibre-signed-file/1`, ML-DSA-65 + Ed25519, both required.
- Every file is signed offline on the owner's computer and published by pull request.
- `history/<id>/<serial>.json` keeps every published file; `source/` the unsigned payloads;
  `notes/` the release notes the list links to.
- `keys/calibre-signing-keys.json` is the public key for reference. Apps **build in** their
  key list; they never trust a key downloaded from here.

Test networks only; CLX has no value.
