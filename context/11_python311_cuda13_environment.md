# Python 3.11 CUDA 13 Environment Rebuild

Generated: `2026-06-14`

## Action

- Removed the old Python 3.14 `.venv`.
- Installed a project-local CPython `3.11.15` runtime under `.uv-python/`.
- Created a new `.venv` from that Python 3.11 runtime.
- Installed the CUDA 13 PyTorch stack and all SecureEdge project dependencies.
- Added `.uv-python/` and `data/graphs/` to `.gitignore`.

## Installed Runtime

```text
Python: 3.11.15
Torch: 2.12.0+cu130
Torch CUDA runtime: 13.0
PyG: 2.8.0
torch-scatter: 2.1.2+pt212cu130
torch-sparse: 0.6.18+pt212cu130
torch-cluster: 1.6.3
NFStream: 6.6.0
scikit-learn: 1.9.0
numpy: 2.4.6
pandas: 3.0.3
```

## CUDA 13 Install Commands Used

```bash
.venv/bin/python -m pip install torch --index-url https://download.pytorch.org/whl/cu130
.venv/bin/python -m pip install torch-geometric torch-scatter torch-sparse \
  -f https://data.pyg.org/whl/torch-2.12.0+cu130.html
.venv/bin/python -m pip install nfstream scikit-learn numpy pandas joblib tqdm
.venv/bin/python -m pip install torch-cluster \
  -f https://data.pyg.org/whl/torch-2.12.0+cu130.html --no-build-isolation
```

`torch-cluster` did not have a matching prebuilt wheel in the CUDA 13/Python 3.11 path, so it was built locally with build isolation disabled.

## Verification

Passed:

```bash
.venv/bin/python -m compileall secureedge tests
.venv/bin/python tests/smoke_checks.py
```

Confirmed imports for:

```text
torch
torch_geometric
torch_scatter
torch_sparse
torch_cluster
nfstream
sklearn
numpy
pandas
joblib
tqdm
```

## Important Caveat

`torch.version.cuda` reports `13.0`, but `torch.cuda.is_available()` is currently `False` because `nvidia-smi` cannot communicate with the NVIDIA driver in the current booted session.

Earlier, `rpm-ostree` staged a system deployment that includes Python 3.11 and NVIDIA driver updates. Bazzite reported:

```text
Changes queued for next boot.
```

After rebooting into the staged deployment, rerun:

```bash
nvidia-smi
.venv/bin/python - <<'PY'
import torch
print(torch.__version__)
print(torch.version.cuda)
print(torch.cuda.is_available())
PY
```

## Notes for Future Work

- Keep `.uv-python/`; the `.venv` Python symlink depends on it.
- Do not commit `.uv-python/`, `.venv/`, `artifacts/`, or `data/graphs/`.
- The CUDA 13 venv is large because PyTorch installs the CUDA runtime libraries inside the environment.
