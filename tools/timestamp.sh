#!/usr/bin/env bash
# Signs timestamp.json for the releases.json on main and publishes it as the asset of the release
# "timestamp" (calibre-core docs/SIGNED_FILES.md section 8). Run by .github/workflows/timestamp.yml.
# Runs in the workflow's folder that holds only the hash-pinned files; Python with -I.
# Copied from calibre-core tools/release/release-list/updates-repo. Test networks only; CLX has no value.
set -euo pipefail
[ -n "${TIMESTAMP_KEY:-}" ] || { echo "STOP: no TIMESTAMP_KEY secret (owner: publish-signed.sh --setup-timestamp)"; exit 1; }
d="$(mktemp -d)"; trap 'rm -rf "$d"' EXIT
umask 077
printf '%s' "$TIMESTAMP_KEY" > "$d/signing-key.json"
TOOL=tools/signed_files.py
# Only a release list that the owner's key signed, still valid, with a correct payload, gets a timestamp.
python3 -I "$TOOL" verify --keys keys/calibre-signing-keys.json --kind release-list --id releases releases.json > "$d/payload.json"
python3 -I - "$TOOL" "$d" <<'PY'
import hashlib, json, sys
from pathlib import Path
sys.path.insert(0, str(Path(sys.argv[1]).parent)); import signed_files as sf
d = Path(sys.argv[2])
problems = sf.release_list_problems(json.loads((d / "payload.json").read_text()))
if problems:
    raise SystemExit("STOP: releases.json payload: " + "; ".join(problems))
outer = json.loads(Path("releases.json").read_text())
stamp = {"releases_serial": json.loads(outer["body"])["serial"],
         "releases_sha256": hashlib.sha256(outer["body"].encode()).hexdigest()}
(d / "stamp.json").write_text(json.dumps(stamp))
PY
if gh release view timestamp >/dev/null 2>&1; then
  mkdir "$d/prev"
  if gh release download timestamp -p timestamp.json -D "$d/prev" 2>/dev/null; then
    PREV=(--previous "$d/prev/timestamp.json")
  else
    PREV=(--first)                 # the serial comes from the clock, so it still rises
  fi
else
  PREV=(--first)
fi
# Never vouch for an OLDER release list than the previous timestamp did (calibre-guardian #207, 10 Nov 2026): an
# older list is still validly signed until it expires (history/releases/1.json until 18 Nov 2026), and stopping
# exactly that "old or frozen list" trick is why the timestamp exists. The same serial must be the same list.
if [ -f "$d/prev/timestamp.json" ]; then
  python3 -I - "$d" <<'PY'
import json, sys
from pathlib import Path
d = Path(sys.argv[1])
now = json.loads((d / "stamp.json").read_text())
try:
    before = json.loads(json.loads((d / "prev" / "timestamp.json").read_text())["body"])["payload"]
    serial, digest = int(before["releases_serial"]), str(before["releases_sha256"])
except (KeyError, TypeError, ValueError) as exc:
    raise SystemExit(f"STOP: the previous timestamp.json cannot be read ({exc}); nothing re-signed")
if now["releases_serial"] < serial:
    raise SystemExit(f"STOP: releases.json on main is serial {now['releases_serial']}, OLDER than serial {serial} "
                     "named by the previous timestamp. An old list reached main: nothing re-signed. Put the newest "
                     "list back on main (through a pull request).")
if now["releases_serial"] == serial and now["releases_sha256"] != digest:
    raise SystemExit(f"STOP: releases.json on main is serial {serial} but not the list the previous timestamp named; "
                     "nothing re-signed.")
print(f"release list serial {now['releases_serial']} (previous timestamp: {serial}): not older")
PY
fi
python3 -I "$TOOL" sign --key-dir "$d" --kind timestamp --id releases-timestamp "${PREV[@]}" "$d/stamp.json" "$d/timestamp.json"
python3 -I "$TOOL" fresh --keys keys/calibre-signing-keys.json releases.json "$d/timestamp.json"
if gh release view timestamp >/dev/null 2>&1; then
  gh release upload timestamp "$d/timestamp.json" --clobber
else
  gh release create timestamp "$d/timestamp.json" --title "Timestamp" --latest=false \
     --notes "timestamp.json: re-signed every 12 hours by the Timestamp workflow. Apps download it from this release. CLX has no value."
fi
echo "timestamp.json published"
