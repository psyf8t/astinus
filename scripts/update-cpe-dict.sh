#!/usr/bin/env bash
# update-cpe-dict.sh — placeholder for the Stage 12 NVD CPE
# dictionary refresher.
#
# Stage 6 ships only a hand-curated bootstrap mapping in
# internal/enrich/cpe/builtin/purl_to_cpe.json. The full NVD CPE
# Dictionary (~1.5 GiB raw, ~200 MiB normalised) is too large to
# embed in the binary; Stage 12 will introduce an `astinus offline-db
# build` command that downloads NVD's official CPE feed
# (https://nvd.nist.gov/products/cpe), normalises it, and writes the
# result into a local on-disk store the cpe enricher can read with
# --offline-db.
#
# Until then this script is a documented stub. Running it prints the
# date of the bundled snapshot and reminds the operator to wait for
# Stage 12 (or to extend purl_to_cpe.json by hand for now).

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MAPPING_FILE="$ROOT_DIR/internal/enrich/cpe/builtin/purl_to_cpe.json"

if [[ ! -f "$MAPPING_FILE" ]]; then
  echo "ERROR: $MAPPING_FILE missing" >&2
  exit 1
fi

snapshot=$(grep '"snapshot":' "$MAPPING_FILE" | head -n1 | sed -E 's/.*"snapshot":\s*"([^"]+)".*/\1/')
echo "Bundled CPE mapping snapshot date: ${snapshot:-unknown}"
echo
echo "The full NVD CPE Dictionary loader lands in Stage 12 (offline-db builder)."
echo "Until then, edit $MAPPING_FILE by hand to add new entries."
echo
echo "Schema:"
echo '  {'
echo '    "purl_type": "<npm|pypi|maven|...>",'
echo '    "purl_namespace": "<optional, e.g. org.apache.logging.log4j>",'
echo '    "purl_name": "<short name>",'
echo '    "vendor": "<NVD vendor>",'
echo '    "product": "<NVD product>"'
echo '  }'
