"""Tests for a2a_audit.setup_models.

These tests mock huggingface_hub so no network I/O occurs.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

# --------------------------------------------------------------------------- #
# helpers                                                                      #
# --------------------------------------------------------------------------- #


def _make_present(tmp_path: Path) -> tuple[Path, Path]:
    """Create stub model files that satisfy the 'already present' checks."""
    deberta_dir = tmp_path / "deberta" / "onnx"
    deberta_dir.mkdir(parents=True)
    (deberta_dir / "model.onnx").write_bytes(b"stub")
    (deberta_dir / "tokenizer.json").write_text("{}", encoding="utf-8")

    gguf_path = tmp_path / "qwen.gguf"
    gguf_path.write_bytes(b"stub")
    return deberta_dir, gguf_path


# --------------------------------------------------------------------------- #
# _deberta_complete / _gguf_complete                                           #
# --------------------------------------------------------------------------- #


def test_deberta_complete_true(tmp_path: Path) -> None:
    from a2a_audit.setup_models import _deberta_complete

    deberta_dir, _ = _make_present(tmp_path)
    assert _deberta_complete(deberta_dir) is True


def test_deberta_complete_false(tmp_path: Path) -> None:
    from a2a_audit.setup_models import _deberta_complete

    assert _deberta_complete(tmp_path / "nonexistent" / "onnx") is False


def test_gguf_complete_true(tmp_path: Path) -> None:
    from a2a_audit.setup_models import _gguf_complete

    _, gguf_path = _make_present(tmp_path)
    assert _gguf_complete(gguf_path) is True


def test_gguf_complete_false(tmp_path: Path) -> None:
    from a2a_audit.setup_models import _gguf_complete

    assert _gguf_complete(tmp_path / "missing.gguf") is False


# --------------------------------------------------------------------------- #
# pull_models — files already present, no download should occur               #
# --------------------------------------------------------------------------- #


def test_pull_models_skips_existing(tmp_path: Path, capsys) -> None:  # type: ignore[type-arg]
    """When both files already exist, pull_models prints 'skipping' and
    never calls snapshot_download or hf_hub_download."""
    deberta_dir, gguf_path = _make_present(tmp_path)

    with (
        patch("huggingface_hub.snapshot_download") as mock_snap,
        patch("huggingface_hub.hf_hub_download") as mock_hub,
    ):
        from a2a_audit import setup_models

        setup_models.pull_models(
            deberta=True,
            gguf=True,
            model_dir=deberta_dir,
            gguf_path=gguf_path,
        )

    mock_snap.assert_not_called()
    mock_hub.assert_not_called()
    captured = capsys.readouterr()
    assert "skipping" in captured.out


def test_pull_models_deberta_only_skips_gguf(tmp_path: Path) -> None:
    """When gguf=False, hf_hub_download is never called."""
    deberta_dir, gguf_path = _make_present(tmp_path)

    with patch("huggingface_hub.hf_hub_download") as mock_hub:
        from a2a_audit import setup_models

        setup_models.pull_models(deberta=True, gguf=False, model_dir=deberta_dir, gguf_path=gguf_path)

    mock_hub.assert_not_called()


def test_pull_models_gguf_only_skips_deberta(tmp_path: Path) -> None:
    """When deberta=False, snapshot_download is never called."""
    deberta_dir, gguf_path = _make_present(tmp_path)

    with patch("huggingface_hub.snapshot_download") as mock_snap:
        from a2a_audit import setup_models

        setup_models.pull_models(deberta=False, gguf=True, model_dir=deberta_dir, gguf_path=gguf_path)

    mock_snap.assert_not_called()


# --------------------------------------------------------------------------- #
# pull_models — files missing, download should be called                      #
# --------------------------------------------------------------------------- #


def test_pull_models_calls_snapshot_when_deberta_missing(tmp_path: Path) -> None:
    deberta_dir = tmp_path / "deberta" / "onnx"  # does not exist
    gguf_path = tmp_path / "qwen.gguf"
    gguf_path.write_bytes(b"stub")  # gguf already present

    with patch("huggingface_hub.snapshot_download") as mock_snap:
        from a2a_audit import setup_models

        setup_models.pull_models(deberta=True, gguf=False, model_dir=deberta_dir, gguf_path=gguf_path)

    mock_snap.assert_called_once()
    call_kwargs = mock_snap.call_args
    assert call_kwargs[1]["repo_id"] == "protectai/deberta-v3-base-prompt-injection-v2"
    assert "onnx/*" in call_kwargs[1]["allow_patterns"]


def test_pull_models_calls_hf_hub_download_when_gguf_missing(tmp_path: Path, capsys) -> None:  # type: ignore[type-arg]
    deberta_dir, _ = _make_present(tmp_path)
    gguf_path = tmp_path / "missing.gguf"  # does not exist

    # hf_hub_download returns the path where the file landed (same location in
    # this case since local_dir is set).
    fake_dest = tmp_path / "Qwen2.5-7B-Instruct-Q4_K_M.gguf"
    fake_dest.write_bytes(b"stub")

    with patch("huggingface_hub.hf_hub_download", return_value=str(fake_dest)) as mock_hub:
        from a2a_audit import setup_models

        setup_models.pull_models(deberta=False, gguf=True, model_dir=deberta_dir, gguf_path=gguf_path)

    mock_hub.assert_called_once()
    call_kwargs = mock_hub.call_args
    assert call_kwargs[1]["repo_id"] == "bartowski/Qwen2.5-7B-Instruct-GGUF"
    assert call_kwargs[1]["filename"] == "Qwen2.5-7B-Instruct-Q4_K_M.gguf"


# --------------------------------------------------------------------------- #
# main() — arg parsing                                                         #
# --------------------------------------------------------------------------- #


def test_main_default_pulls_both(tmp_path: Path) -> None:
    """Running main() with no args should pull both models."""
    deberta_dir, gguf_path = _make_present(tmp_path)

    called_with: list[dict] = []

    def fake_pull(**kwargs: object) -> None:
        called_with.append(dict(kwargs))

    with (
        patch.object(sys, "argv", ["a2a-audit-pull-models"]),
        patch("a2a_audit.setup_models.pull_models", side_effect=fake_pull),
    ):
        from a2a_audit import setup_models

        setup_models.main()

    assert len(called_with) == 1
    assert called_with[0]["deberta"] is True
    assert called_with[0]["gguf"] is True


def test_main_deberta_flag(tmp_path: Path) -> None:
    called_with: list[dict] = []

    def fake_pull(**kwargs: object) -> None:
        called_with.append(dict(kwargs))

    with (
        patch.object(sys, "argv", ["a2a-audit-pull-models", "--deberta"]),
        patch("a2a_audit.setup_models.pull_models", side_effect=fake_pull),
    ):
        from a2a_audit import setup_models

        setup_models.main()

    assert called_with[0]["deberta"] is True
    assert called_with[0]["gguf"] is False


def test_main_gguf_flag(tmp_path: Path) -> None:
    called_with: list[dict] = []

    def fake_pull(**kwargs: object) -> None:
        called_with.append(dict(kwargs))

    with (
        patch.object(sys, "argv", ["a2a-audit-pull-models", "--gguf"]),
        patch("a2a_audit.setup_models.pull_models", side_effect=fake_pull),
    ):
        from a2a_audit import setup_models

        setup_models.main()

    assert called_with[0]["deberta"] is False
    assert called_with[0]["gguf"] is True


def test_main_all_flag(tmp_path: Path) -> None:
    called_with: list[dict] = []

    def fake_pull(**kwargs: object) -> None:
        called_with.append(dict(kwargs))

    with (
        patch.object(sys, "argv", ["a2a-audit-pull-models", "--all"]),
        patch("a2a_audit.setup_models.pull_models", side_effect=fake_pull),
    ):
        from a2a_audit import setup_models

        setup_models.main()

    assert called_with[0]["deberta"] is True
    assert called_with[0]["gguf"] is True


def test_main_exits_nonzero_on_error(capsys) -> None:  # type: ignore[type-arg]
    """main() exits with code 1 when pull_models raises."""
    with (
        patch.object(sys, "argv", ["a2a-audit-pull-models"]),
        patch("a2a_audit.setup_models.pull_models", side_effect=RuntimeError("boom")),
        patch("sys.exit") as mock_exit,
    ):
        from a2a_audit import setup_models

        setup_models.main()

    mock_exit.assert_called_once_with(1)
