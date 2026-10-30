from __future__ import annotations

import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
import uuid
from dataclasses import dataclass
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from . import __version__
from .core import (
    CommunityPaths,
    InstallRecord,
    LiveryDockError,
    PackageAnalysis,
    PreparedSource,
    analyze_package,
    analyze_ptp,
    choose_target_path,
    detect_community_paths,
    find_installed_package,
    install_package,
    install_pmdg_ptp,
    load_registry,
    prepare_source,
    uninstall_record,
)
from .ptp import find_msfs2024_sdk
from .pmdg_native import analyze_pmdg_native, choose_pmdg_native_root, install_pmdg_native
from .win_drop import WindowsDropTarget


@dataclass(slots=True)
class QueueItem:
    key: str
    source: PreparedSource
    analysis: PackageAnalysis
    status: str = "Ready"


class LiveryDockApp(tk.Tk):
    def __init__(self, initial_paths: list[str] | None = None):
        super().__init__()
        self.title(f"LiveryDock {__version__} — MSFS 2024")
        self.geometry("1080x720")
        self.minsize(900, 620)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        self.community_paths = detect_community_paths()
        self.items: dict[str, QueueItem] = {}
        self.prepared_sources: list[PreparedSource] = []
        self.worker_queue: queue.Queue[tuple[str, object]] = queue.Queue()
        self._active_installations = 0
        self._pending_scans = 0
        self.target_mode = tk.StringVar(value="auto")
        self.custom_native = tk.StringVar(value=str(self.community_paths.community2024 or ""))
        self.custom_legacy = tk.StringVar(value=str(self.community_paths.community or ""))
        detected_sdk = find_msfs2024_sdk()
        self.ptp_sdk = tk.StringVar(value=str(detected_sdk or ""))
        self.is_steam = bool(self.community_paths.usercfg and "microsoft.limitless" not in str(self.community_paths.usercfg).lower())
        self.status_var = tk.StringVar(value=f"Detected paths from: {self.community_paths.source}")

        self._setup_style()
        self._build_ui()
        self.after(100, self._drain_worker_queue)
        self.after(200, self._enable_drop)
        self._drop_target = None

        if initial_paths:
            self.after(300, lambda: self.add_paths(initial_paths))

    def _setup_style(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("vista" if os.name == "nt" else "clam")
        except tk.TclError:
            pass
        style.configure("Header.TLabel", font=("Segoe UI", 22, "bold"))
        style.configure("Sub.TLabel", font=("Segoe UI", 10))
        style.configure("Drop.TFrame", relief="ridge", borderwidth=2)
        style.configure("Accent.TButton", font=("Segoe UI", 10, "bold"))

    def _build_ui(self) -> None:
        outer = ttk.Frame(self, padding=16)
        outer.pack(fill="both", expand=True)

        header = ttk.Frame(outer)
        header.pack(fill="x")
        ttk.Label(header, text="LiveryDock", style="Header.TLabel").pack(side="left")
        ttk.Label(
            header,
            text="Safe drag-and-drop livery installer for Microsoft Flight Simulator 2024",
            style="Sub.TLabel",
        ).pack(side="left", padx=(14, 0), pady=(10, 0))

        notebook = ttk.Notebook(outer)
        notebook.pack(fill="both", expand=True, pady=(14, 0))
        install_tab = ttk.Frame(notebook, padding=12)
        managed_tab = ttk.Frame(notebook, padding=12)
        notebook.add(install_tab, text="Install")
        notebook.add(managed_tab, text="Managed Liveries")

        self._build_install_tab(install_tab)
        self._build_managed_tab(managed_tab)

        footer = ttk.Frame(outer)
        footer.pack(side="bottom", fill="x", pady=(8, 0), before=notebook)
        ttk.Label(footer, textvariable=self.status_var).pack(side="left")
        ttk.Button(footer, text="Open log", command=self._open_log).pack(side="right")

    def _build_install_tab(self, parent: ttk.Frame) -> None:
        path_box = ttk.LabelFrame(parent, text="MSFS 2024 folders", padding=10)
        path_box.pack(fill="x")

        ttk.Label(path_box, text="Community2024:").grid(row=0, column=0, sticky="w")
        ttk.Entry(path_box, textvariable=self.custom_native).grid(row=0, column=1, sticky="ew", padx=8)
        ttk.Button(path_box, text="Browse", command=lambda: self._browse_target("native")).grid(row=0, column=2)
        ttk.Label(path_box, text="Legacy Community:").grid(row=1, column=0, sticky="w", pady=(6, 0))
        ttk.Entry(path_box, textvariable=self.custom_legacy).grid(row=1, column=1, sticky="ew", padx=8, pady=(6, 0))
        ttk.Button(path_box, text="Browse", command=lambda: self._browse_target("legacy")).grid(row=1, column=2, pady=(6, 0))
        ttk.Label(path_box, text="MSFS 2024 SDK:").grid(row=2, column=0, sticky="w", pady=(6, 0))
        ttk.Entry(path_box, textvariable=self.ptp_sdk).grid(row=2, column=1, sticky="ew", padx=8, pady=(6, 0))
        ttk.Button(path_box, text="Browse", command=self._browse_sdk).grid(row=2, column=2, pady=(6, 0))
        path_box.columnconfigure(1, weight=1)

        target_row = ttk.Frame(path_box)
        target_row.grid(row=3, column=0, columnspan=3, sticky="w", pady=(10, 0))
        ttk.Label(target_row, text="Install target:").pack(side="left")
        for text, value in (
            ("Auto", "auto"),
            ("Community2024", "community2024"),
            ("Legacy Community", "community"),
        ):
            ttk.Radiobutton(target_row, text=text, value=value, variable=self.target_mode).pack(side="left", padx=(10, 0))

        drop = ttk.Frame(parent, style="Drop.TFrame", padding=18)
        drop.pack(fill="x", pady=12)
        ttk.Label(drop, text="Drop ZIP, RAR, 7Z, PTP, or an extracted livery folder here", font=("Segoe UI", 13, "bold")).pack()
        drop_help = ttk.Label(drop, text="PTP extraction is built in — no PMDG DLL required. Native PMDG 2024 livery ZIPs and multi-ZIP packs install directly; legacy PTP DDS paints use the official SDK for KTX2 conversion.", wraplength=900, justify="center")
        drop_help.pack(pady=(4, 8))
        drop.bind("<Configure>", lambda event: drop_help.configure(wraplength=max(200, event.width - 40)))
        ttk.Button(drop, text="Add package…", command=self._browse_source).pack()

        columns = ("source", "package", "format", "target", "status")
        self.queue_tree = ttk.Treeview(parent, columns=columns, show="headings", selectmode="extended", height=10)
        labels = {
            "source": "Source",
            "package": "Package",
            "format": "Format",
            "target": "Auto target",
            "status": "Status",
        }
        widths = {"source": 230, "package": 260, "format": 120, "target": 135, "status": 170}
        for col in columns:
            self.queue_tree.heading(col, text=labels[col])
            self.queue_tree.column(col, width=widths[col], anchor="w")
        self.queue_tree.pack(fill="both", expand=True)
        self.queue_tree.bind("<<TreeviewSelect>>", self._show_selected_details)

        actions = ttk.Frame(parent)
        actions.pack(side="bottom", fill="x", pady=(10, 0), before=self.queue_tree)
        ttk.Button(actions, text="Remove from list", command=self._remove_selected).pack(side="left")
        ttk.Button(actions, text="Clear", command=self._clear_queue).pack(side="left", padx=8)
        ttk.Button(actions, text="Install selected", style="Accent.TButton", command=self._install_selected).pack(side="right")

        details_box = ttk.LabelFrame(parent, text="Package details", padding=8)
        details_box.pack(side="bottom", fill="x", pady=(10, 0), before=actions)
        self.details = tk.Text(details_box, height=6, wrap="word", state="disabled", font=("Consolas", 9))
        self.details.pack(fill="x")

    def _build_managed_tab(self, parent: ttk.Frame) -> None:
        columns = ("title", "version", "format", "target", "installed")
        self.managed_tree = ttk.Treeview(parent, columns=columns, show="headings", selectmode="browse")
        headings = {
            "title": "Livery / package",
            "version": "Version",
            "format": "Format",
            "target": "Location",
            "installed": "Installed",
        }
        for col in columns:
            self.managed_tree.heading(col, text=headings[col])
            self.managed_tree.column(col, width=170 if col != "title" else 300, anchor="w")
        self.managed_tree.pack(fill="both", expand=True)

        actions = ttk.Frame(parent)
        actions.pack(fill="x", pady=(10, 0))
        ttk.Button(actions, text="Refresh", command=self._refresh_managed).pack(side="left")
        ttk.Button(actions, text="Open folder", command=self._open_managed_folder).pack(side="left", padx=8)
        ttk.Button(actions, text="Uninstall / restore previous", command=self._uninstall_selected).pack(side="right")
        self._refresh_managed()

    def _enable_drop(self) -> None:
        self.update_idletasks()
        self._drop_target = WindowsDropTarget(self, self.add_paths)
        enabled = self._drop_target.enable()
        if not enabled and os.name == "nt":
            self.status_var.set("Window drag-and-drop unavailable; use Add package or drag files onto Run LiveryDock.cmd.")

    def _browse_target(self, kind: str) -> None:
        selected = filedialog.askdirectory(title="Choose MSFS Community folder")
        if selected:
            if kind == "native":
                self.custom_native.set(selected)
            else:
                self.custom_legacy.set(selected)

    def _browse_sdk(self) -> None:
        selected = filedialog.askdirectory(title="Choose MSFS 2024 SDK folder (contains Tools\\bin\\fspackagetool.exe)")
        if selected:
            self.ptp_sdk.set(selected)

    def _browse_source(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Choose livery archives",
            filetypes=[("Livery files", "*.zip *.rar *.7z *.ptp"), ("PMDG PTP", "*.ptp"), ("All files", "*.*")],
        )
        if paths:
            self.add_paths(list(paths))
            return
        folder = filedialog.askdirectory(title="Or choose an extracted livery folder")
        if folder:
            self.add_paths([folder])

    def add_paths(self, paths: list[str]) -> None:
        for raw in paths:
            path = Path(raw)
            placeholder = f"loading-{uuid.uuid4().hex}"
            self._pending_scans += 1
            self.queue_tree.insert("", "end", iid=placeholder, values=(path.name, "Scanning…", "", "", "Working"))
            thread = threading.Thread(target=self._prepare_worker, args=(placeholder, path), daemon=True)
            thread.start()

    def _prepare_worker(self, placeholder: str, path: Path) -> None:
        prepared = None
        try:
            prepared = prepare_source(path)
            if prepared.source_kind == "pmdg-ptp":
                analyses = [analyze_ptp(prepared.source)]
            elif prepared.source_kind in {"pmdg-native", "pmdg-native-bundle"}:
                analyses = [analyze_pmdg_native(prepared.source if not prepared.temporary_root else prepared.root, prepared.source_kind)]
            else:
                analyses = [analyze_package(root) for root in prepared.package_roots]
            self.worker_queue.put(("prepared", (placeholder, prepared, analyses)))
        except Exception as exc:
            if prepared is not None:
                prepared.cleanup()
            self.worker_queue.put(("error", (placeholder, path, exc)))

    def _drain_worker_queue(self) -> None:
        try:
            while True:
                event, payload = self.worker_queue.get_nowait()
                if event == "prepared":
                    self._pending_scans -= 1
                    placeholder, prepared, analyses = payload
                    self._finish_prepared(placeholder, prepared, analyses)
                elif event == "error":
                    self._pending_scans -= 1
                    placeholder, path, exc = payload
                    self._finish_error(placeholder, path, exc)
                elif event == "installed":
                    self._active_installations -= 1
                    key, record = payload
                    self.items[key].status = "Installed"
                    self.queue_tree.set(key, "status", "Installed")
                    self.status_var.set(f"Installed {record.title or record.package_name}")
                    self._refresh_managed()
                elif event == "install_error":
                    self._active_installations -= 1
                    key, exc = payload
                    self.items[key].status = "Failed"
                    self.queue_tree.set(key, "status", f"Failed: {exc}")
                    messagebox.showerror("Installation failed", str(exc))
        except queue.Empty:
            pass
        self.after(100, self._drain_worker_queue)

    def _finish_prepared(self, placeholder: str, prepared: PreparedSource, analyses: list[PackageAnalysis]) -> None:
        if not self.queue_tree.exists(placeholder):
            prepared.cleanup()
            return
        self.queue_tree.delete(placeholder)
        self.prepared_sources.append(prepared)
        for index, analysis in enumerate(analyses):
            key = f"pkg-{uuid.uuid4().hex}"
            status = "Ready" if analysis.is_livery else "Review required"
            item = QueueItem(key=key, source=prepared, analysis=analysis, status=status)
            self.items[key] = item
            self.queue_tree.insert(
                "",
                "end",
                iid=key,
                values=(prepared.source.name, analysis.display_name, analysis.package_format, analysis.target_hint, status),
            )
        self.status_var.set(f"Found {len(analyses)} package(s) in {prepared.source.name}")

    def _finish_error(self, placeholder: str, path: Path, exc: Exception) -> None:
        if self.queue_tree.exists(placeholder):
            self.queue_tree.set(placeholder, "package", "No installable package")
            self.queue_tree.set(placeholder, "status", str(exc))
        self.status_var.set(f"Could not scan {path.name}: {exc}")

    def _show_selected_details(self, _event=None) -> None:
        selected = self.queue_tree.selection()
        if not selected or selected[0] not in self.items:
            return
        item = self.items[selected[0]]
        a = item.analysis
        lines = [
            f"Package: {a.package_name}",
            f"Title: {a.title}",
            f"Creator: {a.creator or '-'}   Version: {a.version or '-'}",
            f"Detected format: {a.package_format}   Auto target: {a.target_hint}",
            "Markers: " + ("; ".join(a.reasons) if a.reasons else "none"),
        ]
        if a.source_kind == "pmdg-ptp":
            lines.append(f"PMDG target package: {a.ptp_target_package or 'auto-detect'}")
            sdk = self.ptp_sdk.get().strip()
            lines.append("PTP engine: built-in (no CabLib.dll / PMDG Operations Center required)")
            lines.append(f"MSFS 2024 SDK: {sdk or 'not detected — required only for legacy DDS → KTX2 conversion'}")
        elif a.source_kind in {"pmdg-native", "pmdg-native-bundle"}:
            lines.append(f"PMDG product: {a.pmdg_product_package or 'validated during install'}")
            lines.append(f"PMDG SimObject: {a.pmdg_airplane_folder or 'auto-detect'}")
            if a.pmdg_livery_id:
                lines.append(f"Livery ID: {a.pmdg_livery_id}")
            if a.pmdg_bundle_entries:
                lines.append(f"Nested liveries: {len(a.pmdg_bundle_entries)}")
            lines.append("Native KTX2 package: SDK conversion is not required")
        if a.dependencies:
            lines.append("Dependencies: " + ", ".join(a.dependencies))
        if a.warnings:
            lines.append("Warnings: " + " | ".join(a.warnings))
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("1.0", "\n".join(lines))
        self.details.configure(state="disabled")

    def _remove_selected(self) -> None:
        if self._active_installations:
            return
        for key in self.queue_tree.selection():
            if key in self.items:
                del self.items[key]
            if self.queue_tree.exists(key):
                self.queue_tree.delete(key)

    def _clear_queue(self) -> None:
        if self._active_installations:
            return
        for key in list(self.queue_tree.get_children()):
            self.queue_tree.delete(key)
        self.items.clear()
        for prepared in self.prepared_sources:
            prepared.cleanup()
        self.prepared_sources.clear()

    def _current_paths(self) -> CommunityPaths:
        return CommunityPaths(
            community2024=Path(self.custom_native.get()).expanduser() if self.custom_native.get().strip() else None,
            community=Path(self.custom_legacy.get()).expanduser() if self.custom_legacy.get().strip() else None,
            source="GUI selection",
        )

    def _target_for(self, analysis: PackageAnalysis) -> tuple[str, Path]:
        paths = self._current_paths()
        if analysis.source_kind == "pmdg-ptp":
            return "community", choose_target_path(paths, "community")
        mode = self.target_mode.get()
        if analysis.source_kind in {"pmdg-native", "pmdg-native-bundle"} and mode == "auto":
            root = choose_pmdg_native_root(paths, analysis)
            kind = "community2024" if paths.community2024 and root.expanduser().resolve() == paths.community2024.expanduser().resolve() else "community"
            return kind, root
        target_kind = analysis.target_hint if mode == "auto" else mode
        return target_kind, choose_target_path(paths, target_kind)

    def _install_selected(self) -> None:
        if self._active_installations:
            self.status_var.set("Installation is running. Wait for it to finish.")
            return
        selected = [key for key in self.queue_tree.selection() if key in self.items]
        if not selected:
            selected = [key for key, item in self.items.items() if item.status in {"Ready", "Review required", "Failed"}]
        if not selected:
            messagebox.showinfo("Nothing to install", "Add a livery package first.")
            return

        requests = []
        for key in selected:
            item = self.items[key]
            a = item.analysis
            if not a.is_livery:
                proceed = messagebox.askyesno(
                    "Package is not clearly a livery",
                    f"{a.display_name} is a valid MSFS package, but LiveryDock did not find a clear livery marker. Install anyway?",
                )
                if not proceed:
                    continue
            try:
                target_kind, target_path = self._target_for(a)
            except Exception as exc:
                messagebox.showerror("Target folder problem", str(exc))
                continue

            sdk = None
            if a.source_kind == "pmdg-ptp":
                # PTP extraction is fully built in. The official SDK is only needed for
                # the legacy DDS -> native MSFS 2024 KTX2 compilation stage.
                sdk_text = self.ptp_sdk.get().strip()
                sdk = Path(sdk_text).expanduser() if sdk_text else find_msfs2024_sdk()
                if sdk is None:
                    messagebox.showerror(
                        "MSFS 2024 SDK required",
                        "LiveryDock can open PMDG .ptp files by itself — no PMDG DLL is needed.\n\n"
                        "This PTP is an MSFS 2020 paint, so its DDS textures must be rebuilt as native MSFS 2024 KTX2. "
                        "Install the official MSFS 2024 SDK, then reopen LiveryDock.\n\n"
                        "Typical SDK folder: C:\\MSFS 2024 SDK\n"
                        "Required file: Tools\\bin\\fspackagetool.exe",
                    )
                    continue
                tool = sdk / "Tools" / "bin" / "fspackagetool.exe"
                if not tool.is_file():
                    tool = sdk / "tools" / "bin" / "fspackagetool.exe"
                if not tool.is_file():
                    messagebox.showerror(
                        "Invalid MSFS 2024 SDK folder",
                        f"fspackagetool.exe was not found under:\n{sdk}\n\n"
                        "Choose the SDK root folder that contains Tools\\bin\\fspackagetool.exe.",
                    )
                    continue
                self.ptp_sdk.set(str(sdk))
            elif a.source_kind in {"pmdg-native", "pmdg-native-bundle"}:
                pass
            else:
                duplicates = find_installed_package(a.package_name, self._current_paths())
                elsewhere = [p for p in duplicates if p.parent.resolve() != target_path.resolve()]
                if elsewhere:
                    proceed = messagebox.askyesno(
                        "Duplicate package detected",
                        "The same package appears in another Community folder:\n\n"
                        + "\n".join(str(p) for p in elsewhere)
                        + "\n\nContinue? Keeping duplicates can cause load-order conflicts.",
                    )
                    if not proceed:
                        continue

            item.status = "Installing"
            self.queue_tree.set(key, "status", "Installing…")
            requests.append((key, item, target_kind, target_path, sdk))
        if requests:
            self._active_installations = len(requests)
            threading.Thread(target=self._install_batch_worker, args=(requests,), daemon=True).start()

    def _install_batch_worker(self, requests: list[tuple]) -> None:
        # Each install updates shared layout and registry files; preserve selection order.
        for request in requests:
            self._install_worker(*request)

    def _install_worker(self, key: str, item: QueueItem, target_kind: str, target_path: Path, sdk: Path | None = None) -> None:
        try:
            if item.analysis.source_kind == "pmdg-ptp":
                record = install_pmdg_ptp(item.analysis, item.source.source, target_path, sdk, steam=self.is_steam)
            elif item.analysis.source_kind in {"pmdg-native", "pmdg-native-bundle"}:
                source_path = item.source.source if not item.source.temporary_root else item.source.root
                record = install_pmdg_native(item.analysis, source_path, target_path)
            else:
                record = install_package(item.analysis, item.source.source, target_path, target_kind)
            self.worker_queue.put(("installed", (key, record)))
        except Exception as exc:
            self.worker_queue.put(("install_error", (key, exc)))

    def _refresh_managed(self) -> None:
        for row in self.managed_tree.get_children():
            self.managed_tree.delete(row)
        self._managed_records: dict[str, InstallRecord] = {}
        try:
            records = load_registry()
        except LiveryDockError as exc:
            self.status_var.set(f"Managed liveries could not be loaded: {exc}")
            return
        for record in reversed(records):
            self._managed_records[record.id] = record
            self.managed_tree.insert(
                "",
                "end",
                iid=record.id,
                values=(record.title or record.package_name, record.version, record.package_format, record.target_kind, record.installed_at),
            )

    def _selected_managed(self) -> InstallRecord | None:
        selection = self.managed_tree.selection()
        if not selection:
            return None
        return self._managed_records.get(selection[0])

    def _open_managed_folder(self) -> None:
        record = self._selected_managed()
        if record:
            self._open_path(Path(record.destination))

    def _uninstall_selected(self) -> None:
        if self._active_installations:
            self.status_var.set("Wait for installation to finish before uninstalling.")
            return
        record = self._selected_managed()
        if not record:
            return
        restore = bool(record.backup)
        message = f"Remove {record.title or record.package_name}?"
        if restore:
            message += "\n\nThe previous version backed up by LiveryDock will be restored."
        if not messagebox.askyesno("Uninstall managed livery", message):
            return
        try:
            uninstall_record(record, restore_backup=True)
            self._refresh_managed()
            self.status_var.set(f"Removed {record.title or record.package_name}")
        except Exception as exc:
            messagebox.showerror("Uninstall failed", str(exc))

    def _open_log(self) -> None:
        from .core import log_path
        path = log_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch(exist_ok=True)
        self._open_path(path)

    def _open_path(self, path: Path) -> None:
        try:
            if os.name == "nt":
                os.startfile(str(path))  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(path)])
            else:
                subprocess.Popen(["xdg-open", str(path)])
        except Exception as exc:
            messagebox.showerror("Could not open path", str(exc))

    def _on_close(self) -> None:
        if self._active_installations or self._pending_scans:
            self.status_var.set("Wait for scanning and installation to finish before closing.")
            return
        if self._drop_target:
            self._drop_target.disable()
        for prepared in self.prepared_sources:
            prepared.cleanup()
        self.destroy()


def run(initial_paths: list[str] | None = None) -> None:
    app = LiveryDockApp(initial_paths=initial_paths)
    app.mainloop()
