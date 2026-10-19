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
- `s3://prod-author-cdn/metadata/nvm-windows/malicious_packages/v1/snapshot/<YYYY-MM-DDTHHMMSSZ>.cbor.gz`
- `s3://prod-author-cdn/metadata/nvm-windows/malicious_packages/v1/delta/<YYYY-MM-DDTHHMMSSZ>.cbor.gz`

`head.cose` stays at a fixed name. The client reads it first. Each snapshot tuple is `(seq, sha256, size, published)` and each delta tuple is the same. `published` is Unix seconds. The object name is that instant in UTC as `YYYY-MM-DDTHHMMSSZ`. The client formats `published` and requests that object. A snapshot replaces the delta list. Later hours append one delta tuple each, so the client can fetch every hour since the snapshot.

`head.cose` is uploaded last. Its cache lifetime is 5 minutes. Snapshots and deltas are immutable.
