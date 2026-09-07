#!/usr/bin/env python3
"""Окно управления torification: старт, стоп, автозапуск, Chrome с PAC."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from torification.control import (  # noqa: E402
    all_running,
    autostart_enabled,
    chrome_launcher,
    cursor_through_tor,
    set_autostart,
    start_all,
    status_all,
    stop_all,
)


def _run_gtk() -> None:
    import gi

    gi.require_version("Gtk", "3.0")
    from gi.repository import GLib, Gtk

    class App(Gtk.Window):
        def __init__(self) -> None:
            super().__init__(title="Torification")
            self.set_default_size(380, 320)
            self.set_border_width(16)
            self.set_resizable(False)

            outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
            self.add(outer)

            self.headline = Gtk.Label()
            self.headline.set_xalign(0)
            outer.pack_start(self.headline, False, False, 0)

            hint = Gtk.Label()
            hint.set_xalign(0)
            hint.set_line_wrap(True)
            hint.set_markup(
                '<span size="small" foreground="#666666">'
                "Пока сервисы включены, они живут до выключения ПК или кнопки «Стоп». "
                "Cursor IDE при «Запустить» идёт через Tor. "
                "После входа в систему поднимаются сами, если включён автозапуск."
                "</span>"
            )
            outer.pack_start(hint, False, False, 0)

            self.rows: dict[str, Gtk.Label] = {}
            grid = Gtk.Grid()
            grid.set_column_spacing(16)
            grid.set_row_spacing(8)
            for i, st in enumerate(status_all()):
                name = Gtk.Label(label=st.label)
                name.set_xalign(0)
                val = Gtk.Label()
                val.set_xalign(1)
                grid.attach(name, 0, i, 1, 1)
                grid.attach(val, 1, i, 1, 1)
                self.rows[st.unit] = val
            outer.pack_start(grid, False, False, 4)

            btns = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            self.btn_start = Gtk.Button(label="Запустить")
            self.btn_stop = Gtk.Button(label="Остановить")
            self.btn_chrome = Gtk.Button(label="Chrome с PAC")
            self.btn_start.get_style_context().add_class("suggested-action")
            self.btn_stop.get_style_context().add_class("destructive-action")
            self.btn_start.connect("clicked", self._on_start)
            self.btn_stop.connect("clicked", self._on_stop)
            self.btn_chrome.connect("clicked", self._on_chrome)
            btns.pack_start(self.btn_start, True, True, 0)
            btns.pack_start(self.btn_stop, True, True, 0)
            outer.pack_start(btns, False, False, 0)
            outer.pack_start(self.btn_chrome, False, False, 0)

            self.auto = Gtk.CheckButton(label="Запускать при входе в систему")
            self.auto.connect("toggled", self._on_auto)
            self._auto_guard = False
            outer.pack_start(self.auto, False, False, 0)

            self.error = Gtk.Label()
            self.error.set_xalign(0)
            self.error.set_line_wrap(True)
            outer.pack_start(self.error, False, False, 0)

            self.connect("destroy", Gtk.main_quit)
            self.refresh()
            GLib.timeout_add_seconds(2, self._tick)

        def _tick(self) -> bool:
            self.refresh()
            return True

        def _set_error(self, text: str) -> None:
            self.error.set_markup(f'<span foreground="#c62828">{text}</span>' if text else "")

        def refresh(self) -> None:
            rows = status_all()
            running = all_running(rows)
            if running:
                self.headline.set_markup('<span size="x-large"><b>●  Работает</b></span>')
            elif any(s.active for s in rows):
                self.headline.set_markup('<span size="x-large"><b>●  Частично</b></span>')
            else:
                self.headline.set_markup('<span size="x-large"><b>○  Остановлено</b></span>')
            for s in rows:
                color = "#2e7d32" if s.active else "#c62828"
                word = "работает" if s.active else "остановлен"
                self.rows[s.unit].set_markup(f'<span foreground="{color}">{word}</span>')
            self.btn_start.set_sensitive(not running)
            self.btn_stop.set_sensitive(any(s.active for s in rows))
            self.btn_chrome.set_sensitive(bool(chrome_launcher()))
            if running and cursor_through_tor():
                self.headline.set_markup(
                    '<span size="x-large"><b>●  Работает</b></span>'
                    '  <span size="small" foreground="#2e7d32">Cursor → Tor</span>'
                )
            self._auto_guard = True
            self.auto.set_active(autostart_enabled(rows))
            self._auto_guard = False

        def _on_start(self, _btn) -> None:
            r = start_all()
            self._set_error("" if r.returncode == 0 else (r.stderr or r.stdout or "не удалось запустить"))
            self.refresh()

        def _on_stop(self, _btn) -> None:
            r = stop_all()
            self._set_error("" if r.returncode == 0 else (r.stderr or r.stdout or "не удалось остановить"))
            self.refresh()

        def _on_chrome(self, _btn) -> None:
            exe = chrome_launcher()
            if not exe:
                self._set_error("chrome-torification не найден")
                return
            subprocess.Popen([exe], start_new_session=True)
            self._set_error("")

        def _on_auto(self, btn) -> None:
            if self._auto_guard:
                return
            r = set_autostart(btn.get_active())
            self._set_error("" if r.returncode == 0 else (r.stderr or r.stdout or "не удалось сменить автозапуск"))
            self.refresh()

    App().show_all()
    Gtk.main()


def _run_tk() -> None:
    import tkinter as tk
    from tkinter import ttk

    root = tk.Tk()
    root.title("Torification")
    root.resizable(False, False)
    pad = {"padx": 16, "pady": 6}

    headline = tk.Label(root, font=("Sans", 16, "bold"))
    headline.grid(row=0, column=0, columnspan=2, sticky="w", **pad)

    tk.Label(
        root,
        text="Пока сервисы включены, они живут до выключения ПК или «Стоп».\n"
        "Cursor IDE при «Запустить» идёт через Tor. Автозапуск — после входа.",
        justify="left",
        fg="#555",
    ).grid(row=1, column=0, columnspan=2, sticky="w", padx=16, pady=(0, 8))

    row_vars: dict[str, tk.StringVar] = {}
    for i, st in enumerate(status_all()):
        tk.Label(root, text=st.label).grid(row=2 + i, column=0, sticky="w", padx=16)
        var = tk.StringVar()
        tk.Label(root, textvariable=var).grid(row=2 + i, column=1, sticky="e", padx=16)
        row_vars[st.unit] = var

    err = tk.StringVar()
    auto_var = tk.BooleanVar()
    auto_guard = {"on": False}

    def refresh() -> None:
        rows = status_all()
        running = all_running(rows)
        if running:
            extra = "  · Cursor → Tor" if cursor_through_tor() else ""
            headline.config(text="●  Работает" + extra, fg="#2e7d32")
        elif any(s.active for s in rows):
            headline.config(text="●  Частично", fg="#ef6c00")
        else:
            headline.config(text="○  Остановлено", fg="#c62828")
        for s in rows:
            row_vars[s.unit].set("работает" if s.active else "остановлен")
        btn_start.config(state="disabled" if running else "normal")
        btn_stop.config(state="normal" if any(s.active for s in rows) else "disabled")
        btn_chrome.config(state="normal" if chrome_launcher() else "disabled")
        auto_guard["on"] = True
        auto_var.set(autostart_enabled(rows))
        auto_guard["on"] = False

    def on_start() -> None:
        r = start_all()
        err.set("" if r.returncode == 0 else (r.stderr or r.stdout or "ошибка запуска"))
        refresh()

    def on_stop() -> None:
        r = stop_all()
        err.set("" if r.returncode == 0 else (r.stderr or r.stdout or "ошибка остановки"))
        refresh()

    def on_chrome() -> None:
        exe = chrome_launcher()
        if exe:
            subprocess.Popen([exe], start_new_session=True)
            err.set("")
        else:
            err.set("chrome-torification не найден")

    def on_auto() -> None:
        if auto_guard["on"]:
            return
        r = set_autostart(auto_var.get())
        err.set("" if r.returncode == 0 else (r.stderr or r.stdout or "ошибка автозапуска"))
        refresh()

    btn_row = 2 + len(row_vars)
    btn_start = ttk.Button(root, text="Запустить", command=on_start)
    btn_stop = ttk.Button(root, text="Остановить", command=on_stop)
    btn_chrome = ttk.Button(root, text="Chrome с PAC", command=on_chrome)
    btn_start.grid(row=btn_row, column=0, sticky="ew", padx=(16, 4), pady=12)
    btn_stop.grid(row=btn_row, column=1, sticky="ew", padx=(4, 16), pady=12)
    btn_chrome.grid(row=btn_row + 1, column=0, columnspan=2, sticky="ew", padx=16)
    ttk.Checkbutton(root, text="Запускать при входе в систему", variable=auto_var, command=on_auto).grid(
        row=btn_row + 2, column=0, columnspan=2, sticky="w", padx=16, pady=8
    )
    tk.Label(root, textvariable=err, fg="#c62828", wraplength=340, justify="left").grid(
        row=btn_row + 3, column=0, columnspan=2, sticky="w", padx=16, pady=(0, 12)
    )

    refresh()

    def loop() -> None:
        refresh()
        root.after(2000, loop)

    root.after(2000, loop)
    root.mainloop()


def main() -> None:
    os.chdir(ROOT)
    try:
        _run_gtk()
    except Exception:
        _run_tk()


if __name__ == "__main__":
    main()
