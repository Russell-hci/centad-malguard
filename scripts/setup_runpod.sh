#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "Runpod setup started at: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Repository: $REPO_ROOT"
echo "Python:"
python --version
PYTHON_BIN=".venv/bin/python"

echo "Creating project directories..."
mkdir -p \
  datasets/raw \
  datasets/processed \
  datasets/splits \
  manifests \
  results/baseline \
  results/robustness \
  results/defenses \
  results/gradcam \
  reports \
  runpod_artifacts/archives \
  logs

echo "Installing Python dependencies..."
if [ ! -d ".venv" ]; then
  python -m venv --system-site-packages .venv
fi
"$PYTHON_BIN" -m pip install --upgrade pip
"$PYTHON_BIN" -m pip install -r requirements.txt

echo "Checking NVIDIA GPU visibility..."
nvidia-smi

echo "Checking PyTorch CUDA support..."
"$PYTHON_BIN" - <<'PY'
import torch

print("torch:", torch.__version__)
print("cuda_available:", torch.cuda.is_available())
print("cuda_version:", torch.version.cuda)
print("cudnn_version:", torch.backends.cudnn.version())

if not torch.cuda.is_available():
    raise SystemExit("PyTorch CUDA support is not available.")

for index in range(torch.cuda.device_count()):
    props = torch.cuda.get_device_properties(index)
    print(
        f"gpu[{index}]: name={props.name}, "
        f"memory_gb={props.total_memory / (1024 ** 3):.2f}, "
        f"capability={props.major}.{props.minor}"
    )
PY

echo "Checking Kaggle CLI availability..."
"$PYTHON_BIN" -m kaggle --version
echo "Kaggle authentication is not checked by setup. Verify access with:"
echo "  .venv/bin/python -m kaggle datasets files ikrambenabd/malimg-original | head -30"

echo "Checking project imports and CLI entry points..."
"$PYTHON_BIN" -m compileall -q scripts preprocessing models evaluation utils training
"$PYTHON_BIN" training/train.py --help >/dev/null

ENV_LOG="manifests/runpod_environment_$(date -u +%Y%m%dT%H%M%SZ).txt"
{
  echo "timestamp_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "repo_root=$REPO_ROOT"
  echo
  echo "python_version:"
  "$PYTHON_BIN" --version
  echo
  echo "nvidia_smi:"
  nvidia-smi
  echo
  echo "pip_freeze:"
  "$PYTHON_BIN" -m pip freeze
} > "$ENV_LOG"

echo "Saved environment log to: $ENV_LOG"
echo "Runpod setup checks completed."
echo "Use this Python for experiments: $REPO_ROOT/$PYTHON_BIN"
