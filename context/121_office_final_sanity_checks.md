# Office Final Sanity Checks

Date: 2026-08-03T02:28:09+00:00

- Final manifest: `artifacts/office_model/office_final_robust_training_manifest.json`
- Manifest hash: `5354c40a9a9e0cbd9b1b9a5018f2b0b8063da3ac06d7cce8595d7a8be035588e`

## Epoch 0 Untrained Validation

- Train steps: `0`
- Validation graphs: `14399`
- Accuracy: `0.039378`
- Macro F1: `0.011967`
- Weighted F1: `0.004408`
- Temporal features masked: `True`

## Final Manifest Overlap

| Pair | Graph ID | Candidate Identity | Flow Hash | Group Key |
| --- | --- | --- | --- | --- |
| train <-> val | 0 | 0 | 0 | 0 |
| train <-> test | 0 | 0 | 0 | 0 |
| val <-> test | 0 | 0 | 0 | 0 |

- Metadata mismatch count: `0`
- Flow hash source: `graph.flow_id_hash with tensor content hash fallback`

## DDoS Metadata Trace

| Split | DDoS subtype | Count |
| --- | --- | ---: |
| train | DDOS-HOIC | 1000 |
| train | DDOS-LOIC-HTTP | 1000 |
| train | DDOS-LOIC-UDP | 1000 |
| val | DDOS-LOIC-HTTP | 10 |
| val | DDOS-LOIC-UDP | 762 |
| test | DDOS-HOIC | 4917 |
| test | DDOS-LOIC-UDP | 652 |

### Validation Trace Examples

| Manifest subtype | Graph subtype | Manifest day | Graph day | Identity match |
| --- | --- | --- | --- | --- |
| DDOS-LOIC-HTTP | DDOS-LOIC-HTTP | Tuesday-20-02-2018 | Tuesday-20-02-2018 | True |
| DDOS-LOIC-HTTP | DDOS-LOIC-HTTP | Tuesday-20-02-2018 | Tuesday-20-02-2018 | True |
| DDOS-LOIC-HTTP | DDOS-LOIC-HTTP | Tuesday-20-02-2018 | Tuesday-20-02-2018 | True |
| DDOS-LOIC-HTTP | DDOS-LOIC-HTTP | Tuesday-20-02-2018 | Tuesday-20-02-2018 | True |
| DDOS-LOIC-HTTP | DDOS-LOIC-HTTP | Tuesday-20-02-2018 | Tuesday-20-02-2018 | True |
| DDOS-LOIC-HTTP | DDOS-LOIC-HTTP | Tuesday-20-02-2018 | Tuesday-20-02-2018 | True |
| DDOS-LOIC-HTTP | DDOS-LOIC-HTTP | Tuesday-20-02-2018 | Tuesday-20-02-2018 | True |
| DDOS-LOIC-HTTP | DDOS-LOIC-HTTP | Tuesday-20-02-2018 | Tuesday-20-02-2018 | True |
| DDOS-LOIC-HTTP | DDOS-LOIC-HTTP | Tuesday-20-02-2018 | Tuesday-20-02-2018 | True |
| DDOS-LOIC-HTTP | DDOS-LOIC-HTTP | Tuesday-20-02-2018 | Tuesday-20-02-2018 | True |
| DDOS-LOIC-UDP | DDOS-LOIC-UDP | Tuesday-20-02-2018 | Tuesday-20-02-2018 | True |
| DDOS-LOIC-UDP | DDOS-LOIC-UDP | Tuesday-20-02-2018 | Tuesday-20-02-2018 | True |
