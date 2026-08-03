#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

mkdir -p artifacts/office_model/final_training_logs artifacts/office_model/training_runs context

LOG_TS="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_LOG="artifacts/office_model/final_training_logs/office_final_training_${LOG_TS}.log"

if [[ ! -f artifacts/office_model/office_final_source_graph_dataset_manifest.json ]]; then
  .venv/bin/python -m secureedge.office.build_graphs \
    --cumulative-manifest artifacts/office_model/office_compact_cumulative_manifest_bruteforce_dos_ddos_diverse_24k.json \
    --manifest-path artifacts/office_model/office_final_source_graph_dataset_manifest.json \
    --train-dir data/graphs/office_final_source_train \
    --val-dir data/graphs/office_final_source_val \
    --test-dir data/graphs/office_final_source_test
fi

.venv/bin/python -m secureedge.office.final_training_manifest \
  --compact-manifest artifacts/office_model/office_compact_cumulative_manifest_bruteforce_dos_ddos_diverse_24k.json \
  --graph-manifest artifacts/office_model/office_final_source_graph_dataset_manifest.json \
  --output artifacts/office_model/office_final_robust_training_manifest.json \
  --report context/120_office_final_robust_training_manifest.md \
  --train-group-cap 1000 \
  --seed 42

export SECUREEDGE_DEVICE="${SECUREEDGE_DEVICE:-cuda}"
export SECUREEDGE_MAX_EPOCHS="${SECUREEDGE_MAX_EPOCHS:-30}"
export SECUREEDGE_EARLY_STOP="${SECUREEDGE_EARLY_STOP:-5}"
export SECUREEDGE_BATCH_SIZE="${SECUREEDGE_BATCH_SIZE:-512}"
export SECUREEDGE_EVAL_BATCH_SIZE="${SECUREEDGE_EVAL_BATCH_SIZE:-512}"
export SECUREEDGE_LABEL_SMOOTHING="${SECUREEDGE_LABEL_SMOOTHING:-0.05}"
export SECUREEDGE_SCHEDULER="${SECUREEDGE_SCHEDULER:-cosine}"
export SECUREEDGE_PRINT_CLASS_EVERY="${SECUREEDGE_PRINT_CLASS_EVERY:-1}"

.venv/bin/python -m secureedge.office.train \
  --graph-manifest artifacts/office_model/office_final_robust_training_manifest.json \
  --checkpoint-path artifacts/office_model/best_office_final_robust_hgnn.pt \
  --history-path artifacts/office_model/office_final_robust_training_history.json \
  2>&1 | tee "$RUN_LOG"

echo "Final training stdout log: ${RUN_LOG}"
echo "Final training history: artifacts/office_model/office_final_robust_training_history.json"
echo "Latest markdown run log is written under context/office-training-logs-XX.md"
