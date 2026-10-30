"""GUI coordination regressions without opening windows or touching MSFS."""
from pathlib import Path
from queue import Queue
from types import SimpleNamespace
from unittest.mock import Mock

from liverydock import app


def test_ptp_worker_uses_captured_sdk_without_tk_access(monkeypatch):
    state = SimpleNamespace(worker_queue=Queue(), is_steam=False)
    item = SimpleNamespace(
        analysis=SimpleNamespace(source_kind="pmdg-ptp"),
        source=SimpleNamespace(source=Path("paint.ptp")),
    )
    install = Mock(return_value="record")
    monkeypatch.setattr(app, "install_pmdg_ptp", install)
    app.LiveryDockApp._install_worker(state, "id", item, "community", Path("Community"), Path("SDK"))
    assert install.call_args.args[-1] == Path("SDK")
    assert state.worker_queue.get_nowait() == ("installed", ("id", "record"))


def test_selected_installs_run_in_order():
    state = SimpleNamespace(_install_worker=Mock())
    app.LiveryDockApp._install_batch_worker(state, [("first",), ("second",)])
    assert [c.args for c in state._install_worker.call_args_list] == [("first",), ("second",)]


def test_cleared_scan_result_cleans_temporary_files():
    state = SimpleNamespace(queue_tree=SimpleNamespace(exists=lambda _: False))
    prepared = SimpleNamespace(cleanup=Mock())
    app.LiveryDockApp._finish_prepared(state, "canceled", prepared, [])
    prepared.cleanup.assert_called_once()


def test_failed_analysis_cleans_prepared_source(monkeypatch):
    state = SimpleNamespace(worker_queue=Queue())
    prepared = SimpleNamespace(source_kind="package", package_roots=[Path("bad")], cleanup=Mock())
    monkeypatch.setattr(app, "prepare_source", Mock(return_value=prepared))
    monkeypatch.setattr(app, "analyze_package", Mock(side_effect=ValueError("invalid")))
    app.LiveryDockApp._prepare_worker(state, "id", Path("paint.zip"))
    prepared.cleanup.assert_called_once()
    assert state.worker_queue.get_nowait()[0] == "error"


def test_readding_same_package_after_removal_has_unique_row_ids():
    rows = {"loading-1", "loading-2"}
    def insert(_parent, _index, *, iid, values):
        assert iid not in rows
        rows.add(iid)
    state = SimpleNamespace(
        queue_tree=SimpleNamespace(exists=rows.__contains__, delete=rows.remove, insert=insert),
        prepared_sources=[], items={}, status_var=Mock(),
    )
    prepared = SimpleNamespace(source=Path("paint.zip"))
    analysis = SimpleNamespace(is_livery=True, package_name="same", display_name="Same", package_format="native-2024", target_hint="community2024")
    app.LiveryDockApp._finish_prepared(state, "loading-1", prepared, [analysis])
    old_key = next(iter(state.items))
    # A removed earlier row makes len(items) reuse a previously assigned value.
    state.items.clear()
    app.LiveryDockApp._finish_prepared(state, "loading-2", prepared, [analysis])
    assert next(iter(state.items)) != old_key
