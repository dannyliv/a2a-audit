"""Model-download helper for a2a-audit.

Downloads the two default local-classifier model weights into the project's
``models/`` directory using huggingface_hub so no shell commands are needed.

Models fetched:
  - DeBERTa  : protectai/deberta-v3-base-prompt-injection-v2  (onnx/ subdir)
               -> models/deberta-injection/onnx/
  - Qwen GGUF: bartowski/Qwen2.5-7B-Instruct-GGUF
               Qwen2.5-7B-Instruct-Q4_K_M.gguf
               -> models/qwen2.5-7b-instruct-q4_k_m.gguf

Entry point: ``a2a-audit-pull-models`` (console_scripts in pyproject.toml).
"""

from __future__ import annotations

import sys
from pathlib import Path

from a2a_audit.backends import DEFAULT_DEBERTA_DIR, DEFAULT_GGUF_PATH

_REPO_ROOT = Path(__file__).resolve().parent.parent

# Canonical HuggingFace coordinates.
_DEBERTA_REPO = "protectai/deberta-v3-base-prompt-injection-v2"
_GGUF_REPO = "bartowski/Qwen2.5-7B-Instruct-GGUF"
_GGUF_FILENAME = "Qwen2.5-7B-Instruct-Q4_K_M.gguf"


def _deberta_complete(model_dir: Path = DEFAULT_DEBERTA_DIR) -> bool:
    """Return True if the DeBERTa ONNX files are already present."""
    return (model_dir / "model.onnx").exists() and (model_dir / "tokenizer.json").exists()


def _gguf_complete(gguf_path: Path = DEFAULT_GGUF_PATH) -> bool:
    """Return True if the GGUF weight file is already present."""
    return gguf_path.exists()


def pull_models(
    *,
    deberta: bool = True,
    gguf: bool = True,
    model_dir: Path | None = None,
    gguf_path: Path | None = None,
) -> None:
    """Download missing model weights.

    Parameters
    ----------
    deberta:
        Fetch the DeBERTa ONNX model when True (default).
    gguf:
        Fetch the Qwen GGUF model when True (default).
    model_dir:
        Override destination for DeBERTa files. Defaults to DEFAULT_DEBERTA_DIR.
    gguf_path:
        Override destination for the GGUF file. Defaults to DEFAULT_GGUF_PATH.
    """
    from huggingface_hub import hf_hub_download, snapshot_download

    deberta_dir = model_dir or DEFAULT_DEBERTA_DIR
    qwen_path = gguf_path or DEFAULT_GGUF_PATH

    if deberta:
        if _deberta_complete(deberta_dir):
            print(f"[deberta] already present at {deberta_dir} — skipping", flush=True)
        else:
            print(f"[deberta] downloading {_DEBERTA_REPO} (onnx/*) ...", flush=True)
            # snapshot_download into the parent of onnx/ so the layout matches
            # DEFAULT_DEBERTA_DIR which is models/deberta-injection/onnx/.
            dest = deberta_dir.parent
            dest.mkdir(parents=True, exist_ok=True)
            snapshot_download(
                repo_id=_DEBERTA_REPO,
                allow_patterns=["onnx/*"],
                local_dir=str(dest),
            )
            print(f"[deberta] saved to {deberta_dir}", flush=True)

    if gguf:
        if _gguf_complete(qwen_path):
            print(f"[gguf] already present at {qwen_path} — skipping", flush=True)
        else:
            print(f"[gguf] downloading {_GGUF_FILENAME} from {_GGUF_REPO} ...", flush=True)
            qwen_path.parent.mkdir(parents=True, exist_ok=True)
            # hf_hub_download places the file in a cache; we move it to the
            # exact target path so DEFAULT_GGUF_PATH resolves correctly.
            import shutil

            cached = hf_hub_download(
                repo_id=_GGUF_REPO,
                filename=_GGUF_FILENAME,
                local_dir=str(qwen_path.parent),
            )
            # hf_hub_download already writes into local_dir when local_dir is
            # set, so the file arrives at qwen_path.parent / _GGUF_FILENAME.
            # Rename if necessary (e.g. case differences).
            arrived = Path(cached)
            if arrived.resolve() != qwen_path.resolve():
                shutil.move(str(arrived), str(qwen_path))
            print(f"[gguf] saved to {qwen_path}", flush=True)


def main() -> None:
    """CLI entry point: ``a2a-audit-pull-models [--deberta] [--gguf] [--all]``."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="a2a-audit-pull-models",
        description=(
            "Download DeBERTa and/or Qwen GGUF model weights into models/. "
            "Skips files that are already present."
        ),
    )
    parser.add_argument(
        "--deberta",
        action="store_true",
        default=False,
        help="Download only the DeBERTa ONNX model.",
    )
    parser.add_argument(
        "--gguf",
        action="store_true",
        default=False,
        help="Download only the Qwen GGUF model.",
    )
    parser.add_argument(
        "--all",
        dest="all_models",
        action="store_true",
        default=False,
        help="Download both models (default when no flag is given).",
    )
    args = parser.parse_args()

    # Default: pull everything when no flag is specified.
    want_deberta = args.deberta or args.all_models or (not args.deberta and not args.gguf)
    want_gguf = args.gguf or args.all_models or (not args.deberta and not args.gguf)

    try:
        pull_models(deberta=want_deberta, gguf=want_gguf)
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)
