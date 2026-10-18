# L-001G Root key rollover (candidate)

Root rotation requires both the previously authenticated Root private key and the successor Root private key to sign the **same domain-separated** transition containing Space, old/new public keys, old/new epoch, issue time and expiration. Only consecutive epoch increases are permitted; replay, wrong Space, expired transition, duplicated keys, altered transcript and either forged signature reject.

`verify_root_rotation_for_spike` only returns a proposed new `ExternallyPinnedRootForSpike`. The new pin must subsequently be committed by an **independent rollback-resistant anchor provider**. It is not automatically saved and must never be imported from the same SQLite backup.

Recovery after total loss of the old Root signing key is NOT solved; emergency recovery and ownership transfers require a separate, formally reviewed multi-party mechanism. A Root key rollover is NOT the same as Resource Owner transfer or delegation revocation. Production admission remains Paused.
