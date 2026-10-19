# Signing

`v1/head.cose` is a COSE_Sign1. CoseSignTool signs the raw head payload with Azure Artifact Signing. The certificate chain is embedded. Deltas and snapshots are not signed on their own. Their SHA-256 and size are inside the signed head.

The workflow uses OIDC. It does not store an Azure client secret.

Add a federated credential on the existing Artifact Signing app registration:

- Issuer: `https://token.actions.githubusercontent.com`
- Subject: `repo:nvm-windows/ossf-malicious-packages:environment:publish`
- Audience: `api://AzureADTokenExchange`

That identity needs `Artifact Signing Certificate Profile Signer` on the account and certificate profile named by `ARTIFACT_SIGNING_ACCOUNT` and `ARTIFACT_SIGNING_CERTIFICATE_PROFILE`.

The R2 objects are:

- `s3://prod-author-cdn/metadata/nvm-windows/malicious_packages/v1/head.cose`
- `s3://prod-author-cdn/metadata/nvm-windows/malicious_packages/v1/snapshot/<seq>.cbor.gz`
- `s3://prod-author-cdn/metadata/nvm-windows/malicious_packages/v1/delta/<seq>.cbor.gz`

`head.cose` is uploaded last. Its cache lifetime is 60 minutes, which is the shortest time between publishes. Snapshots and deltas do not change, and their cache lifetime is 30 days.

When a run writes a snapshot, the signed head lists no deltas. Later runs list every delta published since that snapshot. `state.json` keeps that list so the next head can repeat it. A client that cannot apply the whole list downloads the snapshot.

A size hold opens a pull request from `hold/seq-<n>` that sets `publish_oversize` to true. The pull request body contains `Closes #<issue>`. The next ready publish that used the flag sets it back to false in the same commit as `state.json`. High-impact ALL names are not added by that pull request.
