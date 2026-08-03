# Office BruteForce SSH/FTP Equal 24k Manifest

Date: 2026-08-02

## Objective

Update the selected BruteForce class manifest so both BruteForce subtypes are represented equally:

- `12,000` `SSH-Bruteforce`
- `12,000` `FTP-BruteForce`

This replaces the previous selected BruteForce set, which contained `24,000` `SSH-Bruteforce` graphs and `0` FTP graphs.

## New BruteForce Split

| Split | SSH-Bruteforce | FTP-BruteForce | Total |
| --- | ---: | ---: | ---: |
| train | 10,000 | 10,000 | 20,000 |
| val | 1,000 | 1,000 | 2,000 |
| test | 1,000 | 1,000 | 2,000 |
| Total | 12,000 | 12,000 | 24,000 |

Both subtypes come from:

`Wednesday-14-02-2018`

## Validation

| Check | Result |
| --- | ---: |
| Selected BruteForce graphs | 24,000 |
| Missing selected files | 0 |
| Label/subtype mismatches | 0 |
| Zero-packet selected graphs | 0 |
| Duplicate flow hash surplus | 0 |
| Duplicate compact tensor hash surplus | 1,443 |

## Duplicate Tensor Caveat

The FTP pool contains exactly `12,000` graph files, but those files include `1,443` duplicate compact tensor hashes.

That means exact `12,000 / 12,000` SSH/FTP balance is possible only if we accept the FTP duplicate tensor graphs. Flow hashes remain unique, so these are not duplicate flow IDs, but they are exact compact graph tensor duplicates.

If we require strict tensor-level duplicate freedom, FTP can contribute only `10,557` unique tensor graphs.

## Artifacts

| Artifact | Path |
| --- | --- |
| BruteForce selection JSONL | `artifacts/office_model/balanced_subtype_sets/bruteforce_ssh_ftp_24k_paths.jsonl` |
| BruteForce selection manifest | `artifacts/office_model/balanced_subtype_sets/bruteforce_ssh_ftp_24k_manifest.json` |
| New cumulative manifest variant | `artifacts/office_model/office_compact_cumulative_manifest_bruteforce_dos_ddos_diverse_24k.json` |

## Training Note

Use this cumulative manifest for the next conversion/training step when we want:

- equal SSH/FTP BruteForce selection;
- diverse DoS 24k selection;
- diverse DDoS 24k selection.

`artifacts/office_model/office_compact_cumulative_manifest_bruteforce_dos_ddos_diverse_24k.json`
