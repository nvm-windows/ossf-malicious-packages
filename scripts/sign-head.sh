#!/usr/bin/env bash
set -euo pipefail

payload="${1:?payload}"
output="${2:?output}"
endpoint="${ARTIFACT_SIGNING_ENDPOINT:?}"
account="${ARTIFACT_SIGNING_ACCOUNT:?}"
profile="${ARTIFACT_SIGNING_CERTIFICATE_PROFILE:?}"
tool="${COSESIGNTOOL_TOOLS_DIR:?}/CoseSignTool"

"$tool" sign \
  --payload "$payload" \
  --SignatureFile "$output" \
  --ep \
  --scitt false \
  --cp azure-artifact-signing \
  --aas-endpoint "${endpoint%/}" \
  --aas-account-name "$account" \
  --aas-cert-profile-name "$profile"

test -s "$output"
echo "signed $output"
