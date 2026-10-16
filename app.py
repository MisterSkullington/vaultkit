#!/usr/bin/env python3
"""vaultkit app — a password-health dashboard on top of your KeePassXC vault.

KeePassXC stays the database (and the place you view/edit passwords). This window shows
which passwords are breached, weak, reused or old. All vault access goes through keepassxc-cli via the
same core as the command-line tool; every slow call runs off the UI thread.

Run on Windows without a console window:  pyw app.py
"""
from __future__ import annotations

import getpass
import json
import os
import struct
import subprocess
import sys
import urllib.error
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable

from PySide6.QtCore import (QBuffer, QByteArray, QEvent, QIODevice, QMimeData, QObject,
                            QProcess, QRectF, QRunnable, QSettings, QSize, Qt, QThreadPool, QTimer,
                            QUrl, Signal)
from PySide6.QtGui import (QAction, QActionGroup, QColor, QDesktopServices, QIcon, QIntValidator,
                           QPainter, QPainterPath,
                           QPalette, QPixmap)
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QCheckBox, QComboBox,
                               QFileDialog, QFormLayout,
                               QMenu, QScrollArea, QSystemTrayIcon,
                               QHBoxLayout, QHeaderView, QLabel, QLineEdit,
                               QMainWindow, QPushButton, QSizePolicy, QStackedWidget,
                               QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget)

from PySide6.QtNetwork import QLocalServer, QLocalSocket

sys.path.insert(0, str(Path(__file__).resolve().parent))
import autostart  # noqa: E402
import kpsetup  # noqa: E402
import secretstore  # noqa: E402
import shortcuts  # noqa: E402
import strength  # noqa: E402
import updater  # noqa: E402
import vaultkit as vk  # noqa: E402

HERE = Path(__file__).resolve().parent
UPDATE_CHECK_HOURS = 24
DAILY_CHECK_HOURS = 24     # how often the background check runs
REMINDER_DAYS = 7          # nudge about unfixed problems at most this often
INSTANCE_NAME = f"vaultkit-{getpass.getuser()}"

IDLE_LOCK_MINUTES = 5

# ---------------------------------------------------------------------------- design tokens
@dataclass(frozen=True)
class Theme:
    key: str
    label: str
    dark: bool
    paper: str        # window background
    surface: str      # inputs, table, panels
    ink: str          # text
    muted: str        # secondary text
    line: str         # hairlines
    focus: str        # focus ring, links, primary button
    focus_hover: str
    on_focus: str     # text on the primary button
    disabled: str     # disabled primary button
    selection: str    # selected table row, info banner
    warn_bg: str      # warning banner
    breached: str     # status: password exposed
    risk: str         # status: weak, reused, site breached, old
    info: str         # status: not a password problem (shared names)
    safe: str


# Every theme is checked for 4.5:1 text contrast and 3:1 for status colours (WCAG AA).
THEMES = {t.key: t for t in (
    Theme("mist", "Mist (light)", False,
          paper="#EEF1F4", surface="#FFFFFF", ink="#1C2733", muted="#56657A", line="#D5DCE3",
          focus="#2F5D8A", focus_hover="#264D73", on_focus="#FFFFFF", disabled="#9FB3C8",
          selection="#DCE6F0", warn_bg="#F6E3E1",
          breached="#B3261E", risk="#A8701C", info="#5A5FA8", safe="#2E7D5B"),
    Theme("slate", "Slate (dark)", True,
          paper="#161D24", surface="#1E2731", ink="#E3E9EF", muted="#9AA8B6", line="#2F3B47",
          focus="#7DAEDB", focus_hover="#96BFE4", on_focus="#0E1620", disabled="#3A4856",
          selection="#2A3B4D", warn_bg="#43252A",
          breached="#EF6B5F", risk="#E2A445", info="#9A9EEA", safe="#52B98A"),
    Theme("ember", "Ember (dark, warm)", True,
          paper="#1A1416", surface="#241B1E", ink="#F2E6E3", muted="#B9A29E", line="#3A2C30",
          focus="#E8945A", focus_hover="#F0A876", on_focus="#1A1416", disabled="#5A4440",
          selection="#3A2A2C", warn_bg="#4A2228",
          breached="#FF6577", risk="#F2C14E", info="#B39DF0", safe="#6CC79A"),
    Theme("heather", "Heather (light)", False,
          paper="#F1EEF3", surface="#FFFFFF", ink="#2A2230", muted="#62566A", line="#DDD5E2",
          focus="#6B4C8A", focus_hover="#5A3E75", on_focus="#FFFFFF", disabled="#BCAFC7",
          selection="#E6DDEE", warn_bg="#F6E2E4",
          breached="#B3261E", risk="#9A6210", info="#3F6FB0", safe="#2E7D5B"),
    Theme("contrast", "High contrast", True,
          paper="#000000", surface="#000000", ink="#FFFFFF", muted="#E0E0E0", line="#FFFFFF",
          focus="#FFD400", focus_hover="#FFE45C", on_focus="#000000", disabled="#555555",
          selection="#33330A", warn_bg="#3A0000",
          breached="#FF7070", risk="#FFB000", info="#A9B1FF", safe="#3DDC84"),
)}
THEME_CHOICES = [("system", "Match Windows")] + [(k, t.label) for k, t in THEMES.items()]
T: Theme = THEMES["mist"]  # the active theme; everything reads colours from here

# The app/tray icon is a brand mark: same colours in every theme.
ICON_TILE, ICON_BAR = "#1C2733", "#EEF1F4"
ICON_DOT = {"bad": "#D9372B", "warn": "#E2A445", "ok": "#3FA672"}

FAMILY = "Segoe UI Variable Text"
DISPLAY = "Segoe UI Variable Display"

def build_style(t: Theme) -> str:
    return f"""
QWidget {{ color: {t.ink}; font-family: "{FAMILY}", "Segoe UI", sans-serif; font-size: 10pt; }}
QMainWindow, #page {{ background: {t.paper}; }}
QLabel#muted {{ color: {t.muted}; }}
QLabel#title {{ font-family: "{DISPLAY}", "Segoe UI", sans-serif; font-size: 20pt;
                font-weight: 600; }}
QLabel#verdict {{ font-family: "{DISPLAY}", "Segoe UI", sans-serif; font-size: 28pt;
                  font-weight: 600; }}
QLabel#error {{ color: {t.breached}; }}
QLabel#score {{ font-family: "{DISPLAY}", "Segoe UI", sans-serif; font-size: 28pt;
                font-weight: 700; }}
QLabel#score[tier="safe"] {{ color: {t.safe}; }}
QLabel#score[tier="risk"] {{ color: {t.risk}; }}
QLabel#score[tier="breached"] {{ color: {t.breached}; }}
QLineEdit {{ background: {t.surface}; border: 1px solid {t.line}; border-radius: 6px;
             padding: 7px 9px; selection-background-color: {t.focus}; }}
QLineEdit:focus {{ border: 2px solid {t.focus}; padding: 6px 8px; }}
QPushButton {{ background: {t.surface}; border: 1px solid {t.line}; border-radius: 6px;
               padding: 7px 14px; }}
QPushButton:hover {{ border-color: {t.muted}; }}
QPushButton:focus {{ border: 2px solid {t.focus}; padding: 6px 13px; }}
QPushButton:disabled {{ color: {t.muted}; background: {t.paper}; }}
QPushButton#primary {{ background: {t.focus}; color: {t.on_focus}; border: 1px solid {t.focus}; }}
QPushButton#primary:hover {{ background: {t.focus_hover}; }}
QPushButton#primary:focus {{ border: 2px solid {t.ink}; }}
QPushButton#primary:hover:focus {{ background: {t.focus_hover}; }}
QPushButton#primary:disabled {{ background: {t.disabled}; border-color: {t.disabled}; }}
QPushButton#link {{ background: transparent; border: none; color: {t.focus}; padding: 2px 0;
                    text-align: left; }}
QPushButton#link:hover {{ text-decoration: underline; }}
QPushButton#link:focus {{ border: none; text-decoration: underline; }}
QPushButton#link::menu-indicator {{ image: none; width: 0; }}
QTableWidget {{ background: {t.surface}; border: 1px solid {t.line}; border-radius: 6px;
                gridline-color: transparent; selection-background-color: {t.selection};
                selection-color: {t.ink}; }}
QTableWidget {{ outline: 0; }}
QTableWidget:focus {{ border: 2px solid {t.focus}; }}
QTableWidget::item {{ padding: 6px 8px; border-bottom: 1px solid {t.paper}; }}
QTableWidget::item:focus {{ border: none; border-bottom: 1px solid {t.paper}; }}
QHeaderView::section {{ background: {t.surface}; color: {t.muted}; border: none;
                        border-bottom: 1px solid {t.line}; padding: 8px; font-weight: 600; }}
QCheckBox {{ spacing: 8px; }}
QCheckBox::indicator {{ width: 15px; height: 15px; border: 1px solid {t.muted};
                        border-radius: 3px; background: {t.surface}; }}
QCheckBox::indicator:checked {{ background: {t.focus}; border-color: {t.focus}; }}
QCheckBox::indicator:focus {{ border: 2px solid {t.focus}; }}
QCheckBox::indicator:disabled {{ border-color: {t.line}; background: {t.paper}; }}
QLabel#step {{ font-weight: 600; }}
QLabel#rowtitle {{ font-weight: 600; }}
QWidget#notice {{ background: {t.warn_bg}; border: 1px solid {t.line}; border-radius: 6px; }}
QWidget#guide {{ background: {t.surface}; border: 1px solid {t.line}; border-radius: 6px; }}
QWidget#banner {{ background: {t.selection}; border-bottom: 1px solid {t.line}; }}
QWidget#banner[warn="true"] {{ background: {t.warn_bg}; }}
QLabel#ok {{ color: {t.safe}; }}
QLineEdit#secret {{ font-family: "Cascadia Mono", "Consolas", monospace; font-size: 11pt; }}
QWidget#rules {{ background: {t.surface}; border: 1px solid {t.line}; border-radius: 6px; }}
QScrollArea#scroll, QWidget#scrollbody {{ background: {t.paper}; border: none; }}
QMenu {{ background: {t.surface}; border: 1px solid {t.line}; padding: 4px; }}
QMenu::item {{ padding: 6px 18px; }}
QMenu::item:selected {{ background: {t.selection}; color: {t.ink}; }}
QComboBox {{ background: {t.surface}; }}
QComboBox QAbstractItemView {{ background: {t.surface}; color: {t.ink};
                               selection-background-color: {t.selection}; }}
QToolTip {{ background: {t.surface}; color: {t.ink}; border: 1px solid {t.line}; }}
"""


def swatch(color: str, w: int = 10, h: int = 10) -> QIcon:
    pm = QPixmap(w, h)
    pm.fill(Qt.GlobalColor.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.setBrush(QColor(color))
    p.setPen(Qt.PenStyle.NoPen)
    p.drawRoundedRect(0, 0, w, h, 3, 3)
    p.end()
    return QIcon(pm)


def open_link(url: str) -> None:
    QDesktopServices.openUrl(QUrl(url))


class SecretClipboard(QObject):
    """Copy a secret, keep it out of Windows clipboard history/cloud sync, auto-clear."""
    SECONDS = 45

    def __init__(self) -> None:
        super().__init__()
        self._value: str | None = None
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self.clear)

    def copy(self, value: str) -> None:
        mime = QMimeData()
        mime.setText(value)
        # Same opt-outs KeePassXC uses; ignored on non-Windows platforms.
        win = 'application/x-qt-windows-mime;value="{}"'
        mime.setData(win.format("ExcludeClipboardContentFromMonitorProcessing"), b"\x00")
        mime.setData(win.format("CanIncludeInClipboardHistory"), b"\x00\x00\x00\x00")
        mime.setData(win.format("CanUploadToCloudClipboard"), b"\x00\x00\x00\x00")
        QApplication.clipboard().setMimeData(mime)
        self._value = value
        self._timer.start(self.SECONDS * 1000)

    def clear(self) -> None:
        """Only wipe the clipboard if it still holds what we put there."""
        cb = QApplication.clipboard()
        if self._value is not None and cb.text() == self._value:
            cb.clear()
        self._value = None
        self._timer.stop()


ICON_SIZES = (16, 20, 24, 32, 48, 64, 256)


def icon_pixmap(size: int, status: str | None = None) -> QPixmap:
    """Slate tile with the vault bar; a status dot when there's news (bad / warn / ok)."""
    dot = ICON_DOT.get(status or "")
    pm = QPixmap(size, size)
    pm.fill(Qt.GlobalColor.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor(ICON_TILE))
    p.drawRoundedRect(QRectF(0, 0, size, size), size * 0.2, size * 0.2)
    bar_y, bar_h = size * 0.40, max(size * 0.18, 2.0)
    x, gap = size * 0.16, max(size * 0.04, 1.0)
    for frac, alpha in ((0.17, 255), (0.17, 200), (0.66, 150)):
        w = size * 0.68 * frac
        c = QColor(ICON_BAR)
        c.setAlpha(alpha)
        p.setBrush(c)
        p.drawRoundedRect(QRectF(x, bar_y, w - gap, bar_h), bar_h / 3, bar_h / 3)
        x += w
    if dot:
        r = size * 0.24
        p.setBrush(QColor(ICON_BAR))
        p.drawEllipse(QRectF(size - 2 * r - 1, size - 2 * r - 1, 2 * r + 1, 2 * r + 1))
        p.setBrush(QColor(dot))
        p.drawEllipse(QRectF(size - 2 * r + size * 0.04, size - 2 * r + size * 0.04,
                             2 * r - size * 0.1, 2 * r - size * 0.1))
    p.end()
    return pm


def make_icon(status: str | None = None) -> QIcon:
    icon = QIcon()
    for size in ICON_SIZES:
        icon.addPixmap(icon_pixmap(size, status))
    return icon


def write_ico(path: Path) -> Path:
    """A real multi-size Windows .ico (PNG entries) for shortcuts and Explorer."""
    images = []
    for size in (16, 24, 32, 48, 64, 256):
        data = QByteArray()
        buf = QBuffer(data)
        buf.open(QIODevice.OpenModeFlag.WriteOnly)
        icon_pixmap(size).toImage().save(buf, "PNG")
        buf.close()
        images.append((size, bytes(data)))
    header = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    entries, blobs = b"", b""
    for size, png in images:
        dim = size if size < 256 else 0  # 0 means 256 in the ICO format
        entries += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(png), offset + len(blobs))
        blobs += png
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_bytes(header + entries + blobs)
    os.replace(tmp, path)
    return path


# ---------------------------------------------------------------------------- single instance
def signal_running_instance(show: bool) -> bool:
    """True if vaultkit is already running (and it was asked to show itself if `show`)."""
    sock = QLocalSocket()
    sock.connectToServer(INSTANCE_NAME)
    if not sock.waitForConnected(500):
        return False
    sock.write(b"show" if show else b"ping")
    sock.flush()
    sock.waitForBytesWritten(500)
    # Let the running instance read and hang up first: on Windows a named pipe closed by the
    # writer straight away can lose the message. A hung instance costs at most a second.
    if sock.state() != QLocalSocket.LocalSocketState.UnconnectedState:
        sock.waitForDisconnected(1000)
    sock.abort()
    return True


class InstanceServer(QObject):
    show_requested = Signal()

    def __init__(self) -> None:
        super().__init__()
        self.server = QLocalServer(self)
        QLocalServer.removeServer(INSTANCE_NAME)  # stale socket after a crash (no-op on Windows)
        self.server.listen(INSTANCE_NAME)
        self.server.newConnection.connect(self._incoming)

    def _incoming(self) -> None:
        conn = self.server.nextPendingConnection()
        if conn is None:
            return
        handled = []

        def read():
            if handled or not conn.bytesAvailable():
                return
            handled.append(1)
            if bytes(conn.readAll()).startswith(b"show"):
                self.show_requested.emit()
            conn.disconnectFromServer()
            conn.deleteLater()
        conn.readyRead.connect(read)
        conn.disconnected.connect(read)   # data can arrive together with the hang-up
        read()

    def close(self) -> None:
        self.server.close()


# ---------------------------------------------------------------------------- background jobs
class _Signals(QObject):
    done = Signal(object)
    failed = Signal(str)


class Job(QRunnable):
    def __init__(self, fn: Callable[[], object]):
        super().__init__()
        self.fn = fn
        self.signals = _Signals()

    def run(self) -> None:
        try:
            result = self.fn()
        except Exception as e:  # surfaced to the UI as a plain-language message
            self.signals.failed.emit(friendly_error(e))
            return
        self.signals.done.emit(result)


class Runner(QObject):
    """One worker thread: keepassxc-cli calls never overlap, so the vault file is never
    written by two of our processes at once."""

    def __init__(self) -> None:
        super().__init__()
        self.pool = QThreadPool()
        self.pool.setMaxThreadCount(1)
        self._live: set[Job] = set()

    def submit(self, fn: Callable[[], object], on_done: Callable[[object], None],
               on_fail: Callable[[str], None]) -> None:
        job = Job(fn)
        self._live.add(job)

        def finish(cb, arg):
            self._live.discard(job)
            cb(arg)

        job.signals.done.connect(lambda r: finish(on_done, r))
        job.signals.failed.connect(lambda m: finish(on_fail, m))
        self.pool.start(job)

    def wait(self) -> None:
        self.pool.waitForDone()


def friendly_error(e: Exception) -> str:
    msg = str(e)
    low = msg.lower()
    if isinstance(e, vk.CliError):
        if "invalid credentials" in low or "wrong master password" in low or "hmac" in low:
            return "That password doesn't open this vault. Check Caps Lock and try again."
        if "not found" in low or "no such file" in low or "failed to open" in low:
            return "Can't find the vault file. Check the path, or use Browse to pick it."
        if "no saved master password" in low:
            return "There's no saved password on this PC. Unlock with your master password."
        return f"KeePassXC reported a problem: {msg}"
    if isinstance(e, kpsetup.SetupError):
        return msg
    if isinstance(e, FileNotFoundError):
        return ("KeePassXC isn't installed, or vaultkit can't find it. Press Setup (bottom of "
                "the window) to install it.")
    if isinstance(e, urllib.error.URLError):
        return ("Couldn't reach the breach database (api.pwnedpasswords.com). "
                "Check your internet connection, then press Check now.")
    if isinstance(e, updater.UpdateError):
        return str(e)
    if isinstance(e, secretstore.SecretStoreError):
        return f"Windows couldn't read the saved password: {msg}. Unlock with your master password."
    return f"Something went wrong: {msg}"


# ---------------------------------------------------------------------------- report model
# Most serious first. The first kind an entry has decides its colour and its place in the list.
SEVERITY = ("breached", "sitebreach", "reused", "weak", "similar", "old", "samename")
TIER = {"breached": "breached", "sitebreach": "risk", "reused": "risk", "weak": "risk",
        "similar": "risk", "old": "risk", "samename": "info"}


@dataclass
class Issue:
    name: str
    kind: str          # one of SEVERITY
    problem: str
    changed: str = ""
    tooltip: str = ""

    @property
    def color(self) -> str:
        return getattr(T, TIER[self.kind])

    @property
    def fixable(self) -> bool:
        """Entries that share a title can't be addressed safely by path."""
        return self.kind != "samename" and " [user: " not in self.name


@dataclass
class Report:
    scanned: int
    breached: int      # password seen in a breach, or its site breached since it was set
    at_risk: int       # any other password problem
    samename: int
    issues: list[Issue] = field(default_factory=list)
    checked_at: datetime = field(default_factory=datetime.now)
    rows: dict[str, dict[str, str]] = field(default_factory=dict)  # by path, no passwords
    score: int = 100
    history: list[dict] = field(default_factory=list)  # vk.load_history() points
    sites_error: str = ""

    @property
    def fixable(self) -> list[Issue]:
        return [i for i in self.issues if i.fixable]

    @property
    def safe(self) -> int:
        return max(self.scanned - self.breached - self.at_risk, 0)

    @property
    def needs_changing(self) -> int:
        return self.breached + self.at_risk


def _entries(n: int) -> str:
    return f"{n} other {'entry' if n == 1 else 'entries'}"


def last_changed(row: dict[str, str]) -> str:
    """The password's date if vaultkit set it, else the entry's last edit of any kind."""
    known = vk.password_set_on(row)
    return known.isoformat() if known else (row.get("Last Modified") or "")[:10]


def build_report(res: vk.ScanResult, history: list[dict] | None = None) -> Report:
    changed = {r["Path"]: last_changed(r) for r in res.rows}

    def when(key: str) -> str:
        return changed.get(key.split(" [user: ")[0], "")

    found: dict[str, list[tuple[str, str, str]]] = {}   # key -> [(kind, sentence, tooltip)]

    def add(key: str, kind: str, text: str, tip: str = "") -> None:
        found.setdefault(key, []).append((kind, text, tip))

    for key, n in sorted(res.hits.items(), key=lambda kv: (-kv[1], kv[0])):
        add(key, "breached", f"Found in {n:,} known breach{'es' if n != 1 else ''}.")
    for key, f in sorted(res.sites.items(), key=lambda kv: (not kv[1].after_change, kv[0])):
        add(key, "breached" if f.after_change else "sitebreach", f.text())
    for group in res.reuse:
        for key in group:
            others = [k for k in group if k != key]
            add(key, "reused", f"Same password as {_entries(len(others))}.",
                "Also used by: " + ", ".join(others))
    for key, why in res.weak.items():
        add(key, "weak", why)
    for group in res.similar:
        for key in group:
            others = [k for k in group if k != key]
            add(key, "similar", f"Nearly the same password as {_entries(len(others))}, so "
                "one leak gives the others away.", "Similar to: " + ", ".join(others))
    for key, day in res.old.items():
        add(key, "old", f"Not changed since {day:%b %Y}.")

    issues: list[Issue] = []
    for key, items in found.items():
        items.sort(key=lambda i: SEVERITY.index(i[0]))   # stable: keeps the order added
        tips = [t for _, _, t in items if t]
        issues.append(Issue(key, items[0][0], " ".join(t for _, t, _ in items), when(key),
                            "\n".join(tips)))
    for d in res.dupes:
        n = sum(1 for r in res.rows if r["Path"] == d)
        issues.append(Issue(d, "samename", f"{n} entries share this name. Rename them in "
                            "KeePassXC so each can be fixed on its own.", changed.get(d, "")))
    issues.sort(key=lambda i: SEVERITY.index(i.kind))  # stable within a kind

    kinds = list(res.problems().values())
    breached = kinds.count("breached")
    return Report(res.scanned, breached, len(kinds) - breached, len(res.dupes), issues,
                  rows={r["Path"]: r for r in res.rows}, score=res.score,
                  history=list(history or []), sites_error=res.sites_error)


def run_scan(v: vk.Vault) -> Report:
    """The full check, run on a worker thread: scan, save the report and today's score."""
    res = vk.scan_full(v)
    vk.write_report(res.hits, res.reuse, res.dupes, vk.site_breached(res))
    vk.record_history(res)
    return build_report(res, vk.load_history())


# ---------------------------------------------------------------------------- widgets
class HealthBar(QWidget):
    """The vault in one line: breached / at risk / safe, proportional to entry counts."""

    def __init__(self) -> None:
        super().__init__()
        self.segments: list[tuple[int, str]] = []
        self.setMinimumHeight(14)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setAccessibleName("Vault health bar")

    def sizeHint(self) -> QSize:
        return QSize(400, 14)

    def set_report(self, r: Report | None) -> None:
        self.segments = [] if r is None else [
            (r.breached, "breached"), (r.at_risk, "risk"), (r.safe, "safe")]
        if r:
            self.setAccessibleDescription(
                f"{r.breached} breached, {r.at_risk} at risk, {r.safe} safe")
        self.update()

    def paintEvent(self, _event) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = QRectF(self.rect())
        clip = QPainterPath()
        clip.addRoundedRect(rect, 7, 7)
        p.setClipPath(clip)
        p.fillRect(rect, QColor(T.line))
        total = sum(n for n, _ in self.segments)
        if total:
            x, gap = rect.left(), 2.0
            visible = [(n, c) for n, c in self.segments if n]
            for i, (n, c) in enumerate(visible):
                w = rect.width() * n / total
                seg = QRectF(x, rect.top(), max(w - (gap if i < len(visible) - 1 else 0), 3),
                             rect.height())
                p.fillRect(seg, QColor(getattr(T, c)))
                x += w
        p.end()


def score_tier(score: int, breached: int = 0) -> str:
    """Colour for a score. Never 'safe' green while any password is breached."""
    tier = "safe" if score >= 90 else ("risk" if score >= 60 else "breached")
    return "risk" if breached and tier == "safe" else tier


class Trend(QWidget):
    """A sparkline of the daily health score (vk.load_history), newest on the right."""
    DAYS = 30

    def __init__(self) -> None:
        super().__init__()
        self.scores: list[int] = []
        self.tier = "safe"
        self.setFixedSize(132, 30)
        self.setAccessibleName("Health score trend")

    def set_scores(self, scores: list[int], tier: str) -> None:
        self.scores, self.tier = scores[-self.DAYS:], tier
        self.setAccessibleDescription(", ".join(map(str, self.scores)))
        self.update()

    def paintEvent(self, _event) -> None:
        if len(self.scores) < 2:
            return
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        pad = 4.0
        w, h = self.width() - 2 * pad, self.height() - 2 * pad
        lo, hi = min(self.scores), max(self.scores)
        if hi - lo < 10:  # a flat-ish week shouldn't look like a rollercoaster
            mid = (hi + lo) / 2
            lo, hi = mid - 5, mid + 5
        step = w / (len(self.scores) - 1)
        pts = [(pad + i * step, pad + h - (v - lo) / (hi - lo) * h)
               for i, v in enumerate(self.scores)]
        path = QPainterPath()
        path.moveTo(*pts[0])
        for x, y in pts[1:]:
            path.lineTo(x, y)
        pen = p.pen()
        pen.setColor(QColor(T.muted))
        pen.setWidthF(1.6)
        p.setPen(pen)
        p.drawPath(path)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor(getattr(T, self.tier)))
        p.drawEllipse(QRectF(pts[-1][0] - 3.5, pts[-1][1] - 3.5, 7, 7))
        p.end()


class ScoreCard(QWidget):
    """Health score out of 100, with the trend over recent days."""

    def __init__(self) -> None:
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(2)
        cap = QLabel("Health score")
        cap.setObjectName("muted")
        row = QHBoxLayout()
        row.setSpacing(4)
        self.number = QLabel()
        self.number.setObjectName("score")
        out_of = QLabel("/ 100")
        out_of.setObjectName("muted")
        row.addWidget(self.number)
        row.addWidget(out_of, 0, Qt.AlignmentFlag.AlignBottom)
        row.addStretch(1)
        self.trend = Trend()
        self.change = QLabel()
        self.change.setObjectName("muted")
        lay.addWidget(cap)
        lay.addLayout(row)
        lay.addWidget(self.trend)
        lay.addWidget(self.change)

    def set_report(self, r: Report | None) -> None:
        self.setVisible(r is not None)
        if r is None:
            return
        tier = score_tier(r.score, r.breached)
        self.number.setText(str(r.score))
        self.number.setProperty("tier", tier)
        self.number.style().unpolish(self.number)
        self.number.style().polish(self.number)
        points = r.history[-Trend.DAYS:]
        self.trend.set_scores([h["score"] for h in points], tier)
        self.trend.setVisible(len(points) >= 2)
        self.change.setText(score_change(points))
        self.setAccessibleName(f"Health score {r.score} out of 100. {self.change.text()}")


def score_change(points: list[dict]) -> str:
    """'Up 6 since 3 Oct', in plain words, from the first to the last point shown."""
    if len(points) < 2:
        return "Your trend builds up day by day."
    first, last = points[0], points[-1]
    try:
        since = datetime.fromisoformat(first["at"]).strftime("%d %b").lstrip("0")
    except (KeyError, ValueError):
        since = "your first check"
    d = last["score"] - first["score"]
    if d == 0:
        return f"Same as {since}"
    return f"{'Up' if d > 0 else 'Down'} {abs(d)} since {since}"


class NumberField(QLineEdit):
    """Whole numbers in a range, styled exactly like every other text box."""

    def __init__(self, lo: int, hi: int) -> None:
        super().__init__()
        self.lo, self.hi = lo, hi
        self.setValidator(QIntValidator(lo, hi, self))
        self.setMaximumWidth(90)

    def value(self) -> int:
        try:
            return min(max(int(self.text()), self.lo), self.hi)
        except ValueError:
            return self.lo

    def setValue(self, n: int) -> None:
        self.setText(str(n))


class ThemeMenu(QMenu):
    """The list of themes, with the current one ticked."""
    chosen = Signal(str)

    def __init__(self, title: str = "Theme") -> None:
        super().__init__(title)
        group = QActionGroup(self)
        group.setExclusive(True)
        self.actions_by_key: dict[str, QAction] = {}
        for key, label in THEME_CHOICES:
            act = QAction(label, self, checkable=True)
            group.addAction(act)
            self.addAction(act)
            act.triggered.connect(lambda _checked=False, k=key: self.chosen.emit(k))
            self.actions_by_key[key] = act

    def sync(self, key: str) -> None:
        self.actions_by_key.get(key, self.actions_by_key["system"]).setChecked(True)


def version_label() -> QLabel:
    label = QLabel(f"vaultkit {vk.__version__}")
    label.setObjectName("muted")
    label.setAccessibleName(f"vaultkit version {vk.__version__}")
    return label


def theme_button(menu: ThemeMenu) -> QPushButton:
    b = QPushButton("Theme \u25BE")
    b.setObjectName("link")
    b.setMenu(menu)
    b.setAccessibleName("Choose a colour theme")
    return b


class LegendItem(QWidget):
    def __init__(self, kind: str, label: str) -> None:
        super().__init__()
        self.kind = kind
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(6)
        self.dot = dot = QLabel()
        self.repaint_dot()
        self.text = QLabel(label)
        self.text.setObjectName("muted")
        lay.addWidget(dot)
        lay.addWidget(self.text)

    def repaint_dot(self) -> None:
        self.dot.setPixmap(swatch(getattr(T, self.kind)).pixmap(10, 10))


# ---------------------------------------------------------------------------- pages
class UnlockPage(QWidget):
    unlocked = Signal(object)  # vk.Vault
    setup_requested = Signal()
    create_requested = Signal()

    def __init__(self, runner: Runner, settings: QSettings) -> None:
        super().__init__()
        self.setObjectName("page")
        self.runner, self.settings = runner, settings

        outer = QVBoxLayout(self)
        outer.addStretch(2)
        col = QWidget()
        col.setMaximumWidth(440)
        lay = QVBoxLayout(col)
        lay.setSpacing(10)

        title = QLabel("Unlock your vault")
        title.setObjectName("title")
        self.note = QLabel("Your passwords stay in KeePassXC. This window checks them for "
                           "breaches and reuse.")
        self.note.setObjectName("muted")
        self.note.setWordWrap(True)
        lay.addWidget(title)
        lay.addWidget(self.note)
        lay.addSpacing(8)

        self.kp_notice = QWidget()
        self.kp_notice.setObjectName("notice")
        self.kp_notice.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        kn = QHBoxLayout(self.kp_notice)
        kn.setContentsMargins(14, 10, 14, 10)
        kn_text = QLabel("KeePassXC isn't installed yet. vaultkit needs it: it's where your "
                         "passwords are kept.")
        kn_text.setWordWrap(True)
        self.kp_button = QPushButton("Set up KeePassXC")
        self.kp_button.setObjectName("primary")
        self.kp_button.clicked.connect(self.setup_requested.emit)
        kn.addWidget(kn_text, 1)
        kn.addWidget(self.kp_button)
        self.kp_notice.hide()
        lay.addWidget(self.kp_notice)

        lay.addWidget(QLabel("Vault file"))
        row = QHBoxLayout()
        self.db = QLineEdit(settings.value("db", os.environ.get("VAULTKIT_DB", "")))
        self.db.setPlaceholderText(r"C:\Users\you\Vault\main.kdbx")
        browse = QPushButton("Browse…")
        browse.clicked.connect(self.browse_db)
        row.addWidget(self.db, 1)
        row.addWidget(browse)
        lay.addLayout(row)
        self.create_link = QPushButton("No vault yet? Create one")
        self.create_link.setObjectName("link")
        self.create_link.clicked.connect(self.create_requested.emit)
        lay.addWidget(self.create_link)

        lay.addWidget(QLabel("Master password"))
        self.pw = QLineEdit()
        self.pw.setEchoMode(QLineEdit.EchoMode.Password)
        self.pw.returnPressed.connect(self.unlock_with_password)
        self.pw.setAccessibleName("Master password")
        lay.addWidget(self.pw)

        self.key_toggle = QPushButton("Use a key file too")
        self.key_toggle.setObjectName("link")
        self.key_toggle.clicked.connect(self.show_key_file)
        self.key_row = QWidget()
        kr = QHBoxLayout(self.key_row)
        kr.setContentsMargins(0, 0, 0, 0)
        self.key = QLineEdit(settings.value("key_file", ""))
        self.key.setPlaceholderText("Key file (optional)")
        kb = QPushButton("Browse…")
        kb.clicked.connect(self.browse_key)
        kr.addWidget(self.key, 1)
        kr.addWidget(kb)
        self.key_row.setVisible(bool(self.key.text()))
        self.key_toggle.setVisible(not self.key.text())
        lay.addWidget(self.key_toggle)
        lay.addWidget(self.key_row)

        self.remember = QCheckBox("Remember on this PC for daily checks")
        self.remember.setEnabled(secretstore.supported())
        self.remember_note = QLabel(
            "Encrypted to your Windows login. Programs running as you could read it."
            if secretstore.supported() else "Only available on Windows.")
        self.remember_note.setObjectName("muted")
        self.remember_note.setWordWrap(True)
        lay.addWidget(self.remember)
        lay.addWidget(self.remember_note)

        self.error = QLabel()
        self.error.setObjectName("error")
        self.error.setWordWrap(True)
        self.error.hide()
        lay.addWidget(self.error)

        self.go = QPushButton("Unlock")
        self.go.setObjectName("primary")
        self.go.clicked.connect(self.unlock_with_password)
        self.saved = QPushButton("Unlock with saved password")
        self.saved.clicked.connect(self.unlock_with_saved)
        btns = QHBoxLayout()
        btns.addWidget(self.go)
        btns.addWidget(self.saved)
        btns.addStretch(1)
        lay.addSpacing(4)
        lay.addLayout(btns)

        h = QHBoxLayout()
        h.addStretch(1)
        h.addWidget(col, 3)
        h.addStretch(1)
        outer.addLayout(h)
        outer.addStretch(3)
        self.refresh()

    def refresh(self, message: str = "") -> None:
        self.kp_notice.setVisible(kpsetup.find_cli() is None)
        self.saved.setVisible(secretstore.supported() and secretstore.is_saved())
        self.remember.setChecked(False)
        self.set_busy(False)
        self.show_error(message) if message else self.error.hide()
        # cursor in the first empty field once the window is actually shown
        QTimer.singleShot(0, lambda: (self.pw if self.db.text() else self.db).setFocus())

    def show_key_file(self) -> None:
        self.key_toggle.hide()
        self.key_row.show()
        self.key.setFocus()

    def browse_db(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Choose your vault", self.db.text(),
                                              "KeePass databases (*.kdbx)")
        if path:
            self.db.setText(os.path.normpath(path))

    def browse_key(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Choose your key file", self.key.text())
        if path:
            self.key.setText(os.path.normpath(path))

    def show_error(self, msg: str) -> None:
        self.error.setText(msg)
        self.error.show()

    def set_busy(self, busy: bool, label: str = "Unlocking…") -> None:
        for w in (self.go, self.saved, self.db, self.pw, self.key, self.remember):
            w.setEnabled(not busy and (w is not self.remember or secretstore.supported()))
        self.go.setText(label if busy else "Unlock")

    def _vault(self, **kw) -> vk.Vault | None:
        db = self.db.text().strip().strip('"')
        if not db:
            self.show_error("Choose your vault file first.")
            return None
        return vk.Vault(db=db, key_file=self.key.text().strip().strip('"') or None, **kw)

    def unlock_with_password(self) -> None:
        if not self.pw.text():
            self.show_error("Type your master password.")
            return
        v = self._vault()
        if not v:
            return
        v.set_secret(self.pw.text())
        remember = self.remember.isChecked()
        self.pw.clear()

        def work():
            v.verify()  # never remember a password that doesn't open the vault
            if remember:
                secretstore.save(v._pw or "")
            return v

        self._start(work)

    def unlock_with_saved(self) -> None:
        v = self._vault(use_saved_password=True)
        if v:
            self._start(lambda: (v.unlock(), v.verify(), v)[-1])

    def _start(self, work: Callable[[], object]) -> None:
        self.error.hide()
        self.set_busy(True)
        self.runner.submit(work, self._ok, self._fail)

    def _ok(self, v: vk.Vault) -> None:
        self.settings.setValue("db", v.db)
        self.settings.setValue("key_file", v.key_file or "")
        self.set_busy(False)
        self.unlocked.emit(v)

    def _fail(self, msg: str) -> None:
        self.set_busy(False)
        self.show_error(msg)
        self.pw.setFocus()


class DashboardPage(QWidget):
    lock_requested = Signal()
    fix_requested = Signal(list)  # list[Issue]
    checked = Signal(object)      # Report

    def __init__(self, runner: Runner) -> None:
        super().__init__()
        self.setObjectName("page")
        self.runner = runner
        self.vault: vk.Vault | None = None
        self.report: Report | None = None

        lay = QVBoxLayout(self)
        lay.setContentsMargins(28, 20, 28, 20)
        lay.setSpacing(0)

        top = QHBoxLayout()
        self.dbname = QLabel()
        self.dbname.setObjectName("muted")
        self.lock_btn = QPushButton("Lock")
        self.lock_btn.setFocusPolicy(Qt.FocusPolicy.TabFocus)
        self.lock_btn.clicked.connect(self.lock_requested.emit)
        self.check_btn = QPushButton("Check now")
        self.check_btn.clicked.connect(self.start_check)
        self.fix_btn = QPushButton("Fix passwords")
        self.fix_btn.setObjectName("primary")
        self.fix_btn.clicked.connect(self.fix_all)
        self.fix_btn.hide()
        top.addWidget(self.dbname, 1)
        top.addWidget(self.lock_btn)
        top.addWidget(self.check_btn)
        top.addWidget(self.fix_btn)
        top.setSpacing(8)
        self.top_bar = top
        lay.addLayout(top)
        lay.addSpacing(26)

        self.verdict = QLabel()
        self.verdict.setObjectName("verdict")
        self.verdict.setWordWrap(True)
        self.sub = QLabel()
        self.sub.setObjectName("muted")
        self.sub.setWordWrap(True)
        head = QHBoxLayout()
        head.setSpacing(24)
        words = QVBoxLayout()
        words.setSpacing(4)
        words.addWidget(self.verdict)
        words.addWidget(self.sub)
        words.addStretch(1)
        head.addLayout(words, 1)
        self.score = ScoreCard()
        self.score.hide()
        head.addWidget(self.score, 0, Qt.AlignmentFlag.AlignTop)
        lay.addLayout(head)
        lay.addSpacing(16)

        self.bar = HealthBar()
        lay.addWidget(self.bar)
        lay.addSpacing(10)
        leg = QHBoxLayout()
        leg.setSpacing(18)
        self.leg_breached = LegendItem("breached", "")
        self.leg_risk = LegendItem("risk", "")
        self.leg_safe = LegendItem("safe", "")
        for w in (self.leg_breached, self.leg_risk, self.leg_safe):
            leg.addWidget(w)
        leg.addStretch(1)
        self.legend = QWidget()
        self.legend.setLayout(leg)
        lay.addWidget(self.legend)
        lay.addSpacing(22)

        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["Entry", "Problem", "Last changed"])
        self.table.verticalHeader().hide()
        self.table.setShowGrid(False)
        self.table.setWordWrap(True)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        hh = self.table.horizontalHeader()
        hh.setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        hh.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        hh.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        hh.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        self.table.setColumnWidth(0, 220)
        self.table.cellDoubleClicked.connect(self.fix_row)
        lay.addWidget(self.table, 1)

        self.empty = QLabel()
        self.empty.setObjectName("muted")
        self.empty.setWordWrap(True)
        self.empty.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        lay.addWidget(self.empty, 1)

        foot = QHBoxLayout()
        self.hint = QLabel("Double-click an entry to fix just that one.")
        self.hint.setObjectName("muted")
        self.hint.setWordWrap(True)
        self.forget_btn = QPushButton("Forget saved password")
        self.forget_btn.setObjectName("link")
        self.forget_btn.clicked.connect(self.forget_saved)
        foot.addWidget(self.hint, 1)
        foot.addWidget(self.forget_btn)
        foot.setSpacing(16)
        self.foot = foot
        lay.addSpacing(12)
        lay.addLayout(foot)

    # -- lifecycle
    def open(self, v: vk.Vault) -> None:
        self.vault = v
        self.dbname.setText(Path(v.db).name)
        self.forget_btn.setVisible(secretstore.supported() and secretstore.is_saved())
        self.show_report(None)
        self.start_check()
        QTimer.singleShot(0, self.check_btn.setFocus)

    def close_vault(self) -> None:
        if self.vault:
            self.vault.lock()
        self.vault = None
        self.show_report(None)

    # -- check
    def start_check(self) -> None:
        if not self.vault:
            return
        v = self.vault
        self.check_btn.setEnabled(False)
        self.fix_btn.hide()
        self.check_btn.setText("Checking…")
        self.verdict.setText("Checking your vault…")
        self.sub.setText("Reading entries through KeePassXC, then checking each password "
                         "against known breaches (only the first 5 characters of its hash "
                         "leave this PC) and your sites against the public list of breached "
                         "websites, matched on this PC.")

        self.runner.submit(lambda: run_scan(v), self._checked, self._check_failed)

    def _checked(self, r: Report) -> None:
        self.check_btn.setEnabled(True)
        self.check_btn.setText("Check now")
        if self.vault is None:  # locked while the check was running
            return
        self.show_report(r)
        (self.fix_btn if r.fixable else self.check_btn).setFocus()
        self.checked.emit(r)

    def _check_failed(self, msg: str) -> None:
        self.check_btn.setEnabled(True)
        self.check_btn.setText("Check now")
        self.verdict.setText("The check didn't finish")
        self.sub.setText(msg)

    # -- render
    def show_report(self, r: Report | None) -> None:
        self.report = r
        self.fix_btn.setVisible(bool(r and r.fixable))
        self.check_btn.setObjectName("" if r and r.fixable else "primary")
        self.check_btn.style().unpolish(self.check_btn)
        self.check_btn.style().polish(self.check_btn)
        self.hint.setVisible(bool(r and r.fixable))
        self.bar.set_report(r)
        self.score.set_report(r)
        self.legend.setVisible(r is not None)
        self.table.setRowCount(0)
        if r is None:
            self.verdict.setText("")
            self.sub.setText("")
            self.table.hide()
            self.empty.hide()
            return
        n = r.needs_changing
        self.verdict.setText(
            f"All {r.scanned} passwords look safe" if n == 0 else
            f"{n} password{'s' if n != 1 else ''} need{'' if n != 1 else 's'} changing")
        extra = (f" {r.samename} name{'s are' if r.samename != 1 else ' is'} shared by more "
                 "than one entry." if r.samename else "")
        if r.sites_error:
            extra += (" The list of breached websites couldn't be downloaded, so that part "
                      "was skipped this time.")
        self.sub.setText(f"Checked {r.scanned} passwords at {r.checked_at:%H:%M}.{extra}")
        self.leg_breached.text.setText(f"Breached {r.breached}")
        self.leg_risk.text.setText(f"At risk {r.at_risk}")
        self.leg_safe.text.setText(f"Safe {r.safe}")

        if not r.issues:
            self.table.hide()
            self.empty.setText("Nothing to fix. The daily check will tell you if that changes.")
            self.empty.show()
            return
        self.empty.hide()
        self.table.show()
        self.table.setRowCount(len(r.issues))
        for row, issue in enumerate(r.issues):
            name = QTableWidgetItem(swatch(issue.color), issue.name)
            name.setToolTip(issue.name)
            prob = QTableWidgetItem(issue.problem)
            if issue.tooltip:
                prob.setToolTip(issue.tooltip)
            when = QTableWidgetItem(issue.changed or "—")
            for item in (name, prob, when):
                item.setTextAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
            self.table.setItem(row, 0, name)
            self.table.setItem(row, 1, prob)
            self.table.setItem(row, 2, when)
        self.table.resizeRowsToContents()

    def forget_saved(self) -> None:
        secretstore.forget()
        self.forget_btn.hide()

    def fix_all(self) -> None:
        if self.report and self.report.fixable:
            self.fix_requested.emit(self.report.fixable)

    def fix_row(self, row: int, _col: int = 0) -> None:
        if not self.report or row >= len(self.report.issues):
            return
        issue = self.report.issues[row]
        if issue.fixable:
            self.fix_requested.emit([issue])
        else:
            self.sub.setText(f"{issue.name} can't be fixed from here: rename the entries that "
                             "share its name in KeePassXC first.")



class FixPage(QWidget):
    """One site at a time: new password saved first, change it on the site, confirm."""
    finished = Signal(int)  # passwords changed

    TWOFA = [("none", "None"), ("totp", "Authenticator app"), ("sms", "Text message"),
             ("email", "Email code"), ("webauthn", "Security key or passkey")]

    def __init__(self, runner: Runner, clipboard: SecretClipboard) -> None:
        super().__init__()
        self.setObjectName("page")
        self.runner, self.clip = runner, clipboard
        self.vault: vk.Vault | None = None
        self.queue: list[Issue] = []
        self.rows: dict[str, dict[str, str]] = {}
        self.idx = 0
        self.changed = 0
        self.url = ""

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setObjectName("scroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        body = QWidget()
        body.setObjectName("scrollbody")
        scroll.setWidget(body)
        outer.addWidget(scroll)
        lay = QVBoxLayout(body)
        lay.setContentsMargins(28, 20, 28, 20)
        lay.setSpacing(0)

        top = QHBoxLayout()
        self.back = QPushButton("Back to overview")
        self.back.setObjectName("link")
        self.back.clicked.connect(self.finish)
        self.progress = QLabel()
        self.progress.setObjectName("muted")
        top.addWidget(self.back)
        top.addStretch(1)
        top.addWidget(self.progress)
        lay.addLayout(top)
        lay.addSpacing(22)

        self.title = QLabel()
        self.title.setObjectName("title")
        self.title.setWordWrap(True)
        self.problem = QLabel()
        self.problem.setObjectName("muted")
        self.problem.setWordWrap(True)
        lay.addWidget(self.title)
        lay.addSpacing(4)
        lay.addWidget(self.problem)
        lay.addSpacing(22)

        # step 1
        self.step1 = QLabel("1. Your new password is saved in the vault")
        self.step1.setObjectName("step")
        self.saved_note = QLabel()
        self.saved_note.setObjectName("muted")
        self.saved_note.setWordWrap(True)
        self.step1_box = QWidget()
        row1 = QHBoxLayout(self.step1_box)
        row1.setContentsMargins(0, 0, 0, 0)
        self.secret = QLineEdit()
        self.secret.setObjectName("secret")
        self.secret.setReadOnly(True)
        self.secret.setEchoMode(QLineEdit.EchoMode.Password)
        self.secret.setAccessibleName("New password")
        self.show_btn = QPushButton("Show")
        self.show_btn.clicked.connect(self.toggle_show)
        self.copy_btn = QPushButton("Copy")
        self.copy_btn.clicked.connect(self.copy)
        row1.addWidget(self.secret, 1)
        row1.addWidget(self.show_btn)
        row1.addWidget(self.copy_btn)
        self.step1_all = QWidget()
        s1 = QVBoxLayout(self.step1_all)
        s1.setContentsMargins(0, 0, 0, 20)
        s1.setSpacing(0)
        s1.addWidget(self.step1)
        s1.addSpacing(4)
        s1.addWidget(self.saved_note)
        s1.addSpacing(8)
        s1.addWidget(self.step1_box)
        lay.addWidget(self.step1_all)

        # step 2
        self.step2_box = QWidget()
        s2 = QVBoxLayout(self.step2_box)
        s2.setContentsMargins(0, 0, 0, 20)
        s2.setSpacing(8)
        step2 = QLabel("2. Change it on the site")
        step2.setObjectName("step")
        row2 = QHBoxLayout()
        self.url_label = QLabel()
        self.url_label.setObjectName("muted")
        self.url_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.url_label.setWordWrap(True)
        self.open_btn = QPushButton("Open change page")
        self.open_btn.clicked.connect(self.open_page)
        row2.addWidget(self.url_label, 1)
        row2.addWidget(self.open_btn)
        s2.addWidget(step2)
        s2.addLayout(row2)
        lay.addWidget(self.step2_box)

        # step 3
        self.step3 = QLabel("3. Log out, log back in with the new password, then tell vaultkit")
        self.step3.setObjectName("step")
        self.step3.setWordWrap(True)
        row3 = QHBoxLayout()
        self.accept_btn = QPushButton("The site accepted it")
        self.accept_btn.setObjectName("primary")
        self.accept_btn.clicked.connect(self.accepted)
        self.reject_btn = QPushButton("The site rejected it")
        self.reject_btn.clicked.connect(self.rejected)
        self.skip_btn = QPushButton("Skip for now")
        self.skip_btn.clicked.connect(self.skip)
        row3.setSpacing(8)
        for b in (self.accept_btn, self.reject_btn, self.skip_btn):
            row3.addWidget(b)
        row3.addStretch(1)
        self.status = QLabel()
        self.status.setWordWrap(True)
        lay.addWidget(self.step3)
        lay.addSpacing(6)
        lay.addWidget(self.status)
        lay.addSpacing(10)
        lay.addLayout(row3)
        lay.addSpacing(18)

        # rules
        self.rules_toggle = QPushButton("Password rules for this site")
        self.rules_toggle.setObjectName("link")
        self.rules_toggle.clicked.connect(lambda: self.show_rules(not self.rules.isVisible()))
        lay.addWidget(self.rules_toggle)
        self.rules = QWidget()
        self.rules.setObjectName("rules")
        self.rules.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        form = QFormLayout(self.rules)
        form.setContentsMargins(16, 14, 16, 14)
        form.setVerticalSpacing(10)
        self.length = NumberField(8, 128)
        self.length.setAccessibleName("Password length")
        symrow = QHBoxLayout()
        self.symbols = QLineEdit()
        self.symbols.setAccessibleName("Allowed symbols")
        self.no_symbols = QCheckBox("Letters and numbers only")
        self.no_symbols.toggled.connect(lambda on: self.symbols.setEnabled(not on))
        symrow.addWidget(self.symbols, 1)
        symrow.addWidget(self.no_symbols)
        self.change_url = QLineEdit()
        self.change_url.setPlaceholderText("Leave blank to use the site's standard change page")
        self.twofa = QComboBox()
        for key, label in self.TWOFA:
            self.twofa.addItem(label, key)
        self.save_rules_btn = QPushButton("Save rules and make a new password")
        self.save_rules_btn.clicked.connect(self.save_rules)
        form.addRow("Length", self.length)
        form.addRow("Allowed symbols", symrow)
        form.addRow("Change page", self.change_url)
        form.addRow("Two-step login", self.twofa)
        form.addRow("", self.save_rules_btn)
        lay.addSpacing(6)
        lay.addWidget(self.rules)
        lay.addStretch(1)
        self.rules.hide()

    # -- lifecycle
    def start(self, vault: vk.Vault, issues: list[Issue], rows: dict[str, dict[str, str]]) -> None:
        self.vault, self.queue, self.rows = vault, list(issues), rows
        self.idx, self.changed = 0, 0
        self.load_current()

    def reset(self) -> None:
        """Called on lock: forget everything secret this page holds."""
        self.clip.clear()
        self.secret.clear()
        self.vault = None
        self.queue = []

    def finish(self) -> None:
        self.clip.clear()
        self.secret.clear()
        self.finished.emit(self.changed)

    @property
    def entry(self) -> str:
        return self.queue[self.idx].name

    def set_busy(self, busy: bool, text: str = "") -> None:
        for w in (self.accept_btn, self.reject_btn, self.skip_btn, self.copy_btn,
                  self.show_btn, self.open_btn, self.save_rules_btn):
            w.setEnabled(not busy)
        if busy:
            self.say(text)

    def say(self, text: str, kind: str = "muted") -> None:
        self.status.setObjectName(kind)
        self.status.style().unpolish(self.status)
        self.status.style().polish(self.status)
        self.status.setText(text)
        self.status.setVisible(bool(text))

    def show_rules(self, on: bool) -> None:
        self.rules.setVisible(on)
        self.rules_toggle.setText("Hide password rules" if on else "Password rules for this site")

    # -- per entry
    def load_current(self) -> None:
        if self.idx >= len(self.queue):
            self.finish()
            return
        issue = self.queue[self.idx]
        self.progress.setText(f"{self.idx + 1} of {len(self.queue)}")
        self.title.setText(issue.name)
        self.problem.setText(issue.problem)
        self.secret.clear()
        self.secret.setEchoMode(QLineEdit.EchoMode.Password)
        self.show_btn.setText("Show")
        self.show_rules(False)
        self.set_actions(rejected=False)
        v, entry, row = self.vault, issue.name, self.rows.get(issue.name)

        def work():
            info = vk.site_info(v, entry, row)
            pend = vk.pending_path(entry)
            resumed = v.exists(pend)
            if not resumed:
                vk.start_rotation(v, entry, info)
            return info, v.attr(pend, "Password"), resumed

        self.set_busy(True, "Making a new password and saving it in your vault…")
        self.runner.submit(work, self._loaded, self._failed)

    def _loaded(self, result) -> None:
        info, pw, resumed = result
        if self.vault is None:
            return
        self.set_busy(False)
        self.secret.setText(pw)
        prof = info.profile
        self.saved_note.setText(
            "This is the one saved last time. It's still waiting to be used."
            if resumed else
            "It's stored next to the old one, so nothing is lost if the site change fails.")
        self.url = vk.change_url_for(prof, info.url)
        self.url_label.setText(self.url or "This entry has no web address. Open the site and "
                               "find its password settings.")
        self.open_btn.setEnabled(bool(self.url))
        self.fill_rules(prof)
        twofa = dict(self.TWOFA).get(prof.twofa, prof.twofa)
        self.say(f"Have your {twofa.lower()} ready: the site may ask for it."
                 if prof.twofa != "none" else "")
        self.copy()
        self.accept_btn.setFocus()

    def _failed(self, msg: str) -> None:
        self.set_busy(False)
        self.say(msg, "error")

    def fill_rules(self, prof: vk.Profile) -> None:
        self.length.setValue(prof.length)
        self.no_symbols.setChecked(not prof.symbols)
        self.symbols.setText(prof.symbols or vk.DEFAULT_SYMBOLS)
        self.change_url.setText(prof.change_url)
        self.twofa.setCurrentIndex(max(self.twofa.findData(prof.twofa), 0))

    def set_actions(self, rejected: bool) -> None:
        self.step1_all.setVisible(not rejected)
        self.step2_box.setVisible(not rejected)
        self.accept_btn.setVisible(not rejected)
        self.reject_btn.setVisible(not rejected)
        self.rules_toggle.setVisible(not rejected)
        self.step3.setText("Make a password this site will accept" if rejected else
                           "3. Log out, log back in with the new password, then tell vaultkit")
        self.save_rules_btn.setObjectName("primary" if rejected else "")
        self.save_rules_btn.style().unpolish(self.save_rules_btn)
        self.save_rules_btn.style().polish(self.save_rules_btn)

    # -- actions
    def toggle_show(self) -> None:
        hidden = self.secret.echoMode() == QLineEdit.EchoMode.Password
        self.secret.setEchoMode(QLineEdit.EchoMode.Normal if hidden
                                else QLineEdit.EchoMode.Password)
        self.show_btn.setText("Hide" if hidden else "Show")

    def copy(self) -> None:
        if self.secret.text():
            self.clip.copy(self.secret.text())
            self.copy_btn.setText("Copied")
            QTimer.singleShot(2000, lambda: self.copy_btn.setText("Copy"))

    def open_page(self) -> None:
        if self.url:
            open_link(self.url)

    def accepted(self) -> None:
        v, entry = self.vault, self.entry
        self.set_busy(True, "Saving…")
        self.runner.submit(lambda: vk.commit_rotation(v, entry), self._committed, self._failed)

    def _committed(self, _r) -> None:
        self.changed += 1
        self.clip.clear()
        self.idx += 1
        self.load_current()

    def rejected(self) -> None:
        v, entry = self.vault, self.entry
        self.set_busy(True, "Discarding the new password…")
        self.runner.submit(lambda: vk.abort_rotation(v, entry), self._discarded, self._failed)

    def _discarded(self, _r) -> None:
        self.set_busy(False)
        self.clip.clear()
        self.secret.clear()
        self.set_actions(rejected=True)
        self.show_rules(True)
        self.say("The new password was discarded and your old one is unchanged. Sites often "
                 "limit length or symbols: check what this site allows, set it below, then "
                 "make a new password. Or skip this site for now.")
        self.length.setFocus()

    def skip(self) -> None:
        self.clip.clear()
        self.idx += 1
        self.load_current()

    def save_rules(self) -> None:
        prof = vk.Profile(length=self.length.value(),
                          symbols="" if self.no_symbols.isChecked() else self.symbols.text().strip(),
                          change_url=self.change_url.text().strip(),
                          twofa=self.twofa.currentData())
        try:
            vk.generate_password(prof.length, prof.symbols)
        except ValueError as e:
            self.say(f"Those rules don't work: {e}.", "error")
            return
        v, entry = self.vault, self.entry

        def work():
            notes = vk.upsert_profile(v.attr(entry, "Notes"), prof)
            v.set_notes(entry, notes)
            pend = vk.pending_path(entry)
            if v.exists(pend):
                vk.abort_rotation(v, entry)
            info = vk.SiteInfo(v.attr(entry, "UserName"), v.attr(entry, "URL"), notes)
            vk.start_rotation(v, entry, info)
            return info, v.attr(pend, "Password"), False

        self.set_busy(True, "Saving the rules and making a new password…")
        self.runner.submit(work, self._regenerated, self._failed)

    def _regenerated(self, result) -> None:
        self._loaded(result)
        self.set_actions(rejected=False)
        self.say("Rules saved. A new password that follows them is ready and copied.", "ok")

# ---------------------------------------------------------------------------- setup
class Progress(QObject):
    """Progress lines from a worker thread, delivered on the UI thread (queued signal)."""
    message = Signal(str)


class SetupRow(QWidget):
    """One check: status dot, title, plain-words detail, and its fix button."""

    def __init__(self, check: kpsetup.Check) -> None:
        super().__init__()
        self.check = check
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 8, 0, 8)
        lay.setSpacing(12)
        self.dot = QLabel()
        self.dot.setFixedWidth(12)
        lay.addWidget(self.dot, 0, Qt.AlignmentFlag.AlignTop)
        words = QVBoxLayout()
        words.setSpacing(2)
        title = QLabel(check.title)
        title.setObjectName("rowtitle")
        self.detail = QLabel(check.detail)
        self.detail.setObjectName("muted")
        self.detail.setWordWrap(True)
        words.addWidget(title)
        words.addWidget(self.detail)
        lay.addLayout(words, 1)
        self.button = QPushButton(check.action)
        self.button.setVisible(bool(check.action))
        if check.ok is False:
            self.button.setObjectName("primary")
        lay.addWidget(self.button, 0, Qt.AlignmentFlag.AlignTop)
        state = {True: "done", False: "needs attention", None: "information"}[check.ok]
        self.setAccessibleName(f"{check.title}: {state}. {check.detail}")
        self.repaint_dot()

    def repaint_dot(self) -> None:
        color = {True: T.safe, False: T.risk, None: T.muted}[self.check.ok]
        self.dot.setPixmap(swatch(color).pixmap(10, 10))


class SetupPage(QWidget):
    """KeePassXC installed and set up the recommended way, plus vaultkit's own options."""
    back_requested = Signal()
    create_requested = Signal()
    autostart_requested = Signal()

    def __init__(self, runner: Runner, settings: QSettings) -> None:
        super().__init__()
        self.setObjectName("page")
        self.runner, self.settings = runner, settings
        self.checks: list[kpsetup.Check] = []
        self.rows: list[SetupRow] = []
        self.busy = False
        self.progress = Progress()
        self.progress.message.connect(self.say)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(28, 20, 28, 20)
        outer.setSpacing(0)
        top = QHBoxLayout()
        back = QPushButton("Back")
        back.setObjectName("link")
        back.clicked.connect(self.back_requested.emit)
        top.addWidget(back)
        top.addStretch(1)
        self.recheck = QPushButton("Check again")
        self.recheck.clicked.connect(self.refresh)
        top.addWidget(self.recheck)
        outer.addLayout(top)
        outer.addSpacing(16)
        title = QLabel("Setup")
        title.setObjectName("title")
        sub = QLabel("KeePassXC installed and set up the way vaultkit recommends. Nothing here "
                     "reads your passwords.")
        sub.setObjectName("muted")
        sub.setWordWrap(True)
        outer.addWidget(title)
        outer.addSpacing(4)
        outer.addWidget(sub)
        outer.addSpacing(10)
        self.status = QLabel()
        self.status.setObjectName("muted")
        self.status.setWordWrap(True)
        self.status.hide()
        outer.addWidget(self.status)
        outer.addSpacing(6)

        self.body = QWidget()
        self.body.setObjectName("scrollbody")
        self.list = QVBoxLayout(self.body)
        self.list.setContentsMargins(0, 0, 8, 0)
        self.list.setSpacing(0)
        self.list.addStretch(1)
        scroll = QScrollArea()
        scroll.setObjectName("scroll")
        scroll.setWidgetResizable(True)
        scroll.setWidget(self.body)
        outer.addWidget(scroll, 1)

        # finishing the vault's encryption settings in KeePassXC (keepassxc-cli can't)
        self.guide = QWidget()
        self.guide.setObjectName("guide")
        g = QVBoxLayout(self.guide)
        g.setContentsMargins(16, 12, 16, 12)
        g.setSpacing(6)
        gt = QLabel("Make your vault much harder to crack (one time, about a minute)")
        gt.setObjectName("rowtitle")
        gt.setWordWrap(True)
        g.addWidget(gt)
        self.guide_steps = QLabel()
        self.guide_steps.setWordWrap(True)
        self.guide_steps.setTextFormat(Qt.TextFormat.PlainText)
        g.addWidget(self.guide_steps)
        gb = QHBoxLayout()
        self.open_kp = QPushButton("Open vault in KeePassXC")
        self.open_kp.clicked.connect(self.open_in_keepassxc)
        gb.addWidget(self.open_kp)
        gb.addStretch(1)
        g.addLayout(gb)
        self.guide.hide()
        self.list.insertWidget(0, self.guide)
        self.guide_wanted = False

    # -- checks
    def db(self) -> str:
        return (self.settings.value("db", "") or "").strip().strip('"')

    def refresh(self) -> None:
        if self.busy:
            return
        self.recheck.setEnabled(False)
        db = self.db()
        self.runner.submit(lambda: self._collect(db), self.show_checks, self._failed)

    @staticmethod
    def _collect(db: str) -> list[kpsetup.Check]:
        checks = kpsetup.run_checks(db or None)
        if autostart.supported():
            on = autostart.is_enabled()
            checks.append(kpsetup.Check(
                "vk_autostart", "vaultkit starts with Windows", on,
                "So the daily check runs without you opening anything." if on else
                "The daily check only runs while vaultkit is open.", "" if on else "Turn on"))
        if secretstore.supported():
            saved = secretstore.is_saved()
            checks.append(kpsetup.Check(
                "remember", "Daily checks without unlocking", True if saved else None,
                "Your master password is saved for this, encrypted to your Windows login."
                if saved else "Optional: tick 'Remember on this PC' when you next unlock."))
        return checks

    def show_checks(self, checks: list[kpsetup.Check]) -> None:
        self.recheck.setEnabled(not self.busy)
        self.checks = checks
        for row in self.rows:
            self.list.removeWidget(row)
            row.deleteLater()
        self.rows = []
        self.list.removeWidget(self.guide)
        for ch in checks:
            row = SetupRow(ch)
            row.button.clicked.connect(lambda _=False, c=ch: self.act(c))
            row.button.setEnabled(not self.busy)
            self.list.insertWidget(self.list.count() - 1, row)  # before the stretch
            self.rows.append(row)
            if ch.key == "vault":
                self.list.insertWidget(self.list.count() - 1, self.guide)
        vault = self.check("vault")
        needs_guide = vault is not None and vault.action == "Show me how"
        self.guide_steps.setText("\n".join(f"{n}. {t}" for n, t in
                                           enumerate(kpsetup.strengthen_steps(), 1)))
        self.guide.setVisible(needs_guide and self.guide_wanted)

    def _failed(self, msg: str) -> None:
        self.recheck.setEnabled(not self.busy)
        self.say(msg, error=True)

    def check(self, key: str) -> kpsetup.Check | None:
        return next((c for c in self.checks if c.key == key), None)

    def row(self, key: str) -> SetupRow | None:
        return next((r for r in self.rows if r.check.key == key), None)

    def repaint(self) -> None:
        for row in self.rows:
            row.repaint_dot()

    # -- fixes
    def say(self, text: str, error: bool = False) -> None:
        self.status.setObjectName("error" if error else "muted")
        self.status.style().unpolish(self.status)
        self.status.style().polish(self.status)
        self.status.setText(text)
        self.status.setVisible(bool(text))

    def act(self, ch: kpsetup.Check) -> None:
        if ch.key == "vault":
            if ch.action == "Create a vault":
                self.create_requested.emit()
            else:
                self.guide_wanted = not self.guide.isVisible()
                self.guide.setVisible(self.guide_wanted)
            return
        if ch.key == "extension":
            open_link(kpsetup.EXTENSION_URL)
            return
        if ch.key == "vk_autostart":
            self.autostart_requested.emit()
            self.refresh()
            return
        jobs = {
            "keepassxc": (self._install, "Getting KeePassXC…"),
            "settings": (kpsetup.apply_settings, "Changing KeePassXC's settings…"),
            "connector": (lambda: self._need_cli(kpsetup.register_connector),
                          "Connecting browsers…"),
            "autostart": (lambda: self._need_cli(kpsetup.enable_keepassxc_autostart),
                          "Turning it on…"),
        }
        if ch.key in jobs:
            self.run_fix(*jobs[ch.key])

    @staticmethod
    def _need_cli(fn: Callable[[Path], object]) -> object:
        cli = kpsetup.find_cli()
        if cli is None:
            raise kpsetup.SetupError("Install KeePassXC first.")
        return fn(cli)

    def _install(self) -> None:
        """Install, then the recommended setup straight away (as install.ps1 does)."""
        cli = kpsetup.install_keepassxc(progress=self.progress.message.emit)
        if not kpsetup.keepassxc_running():
            kpsetup.apply_settings()
        if kpsetup.supported():
            if kpsetup.connector_problem():
                kpsetup.register_connector(cli)
            if not kpsetup.keepassxc_autostarts():
                kpsetup.enable_keepassxc_autostart(cli)

    def run_fix(self, work: Callable[[], object], text: str) -> None:
        self.busy = True
        for row in self.rows:
            row.button.setEnabled(False)
        self.recheck.setEnabled(False)
        self.say(text)

        def done(_r) -> None:
            self.busy = False
            self.say("Done.")
            self.refresh()

        def failed(msg: str) -> None:
            self.busy = False
            self.say(msg, error=True)
            self.refresh()

        self.runner.submit(work, done, failed)

    def open_in_keepassxc(self) -> None:
        cli = kpsetup.find_cli()
        if cli is None:
            self.say("Install KeePassXC first.", error=True)
            return
        args = [self.db()] if self.db() else []
        if not QProcess.startDetached(str(kpsetup.gui_exe(cli)), args):
            self.say("Couldn't open KeePassXC. Open it from the Start menu instead.", error=True)

    def show_vault_guide(self) -> None:
        """After creating a vault: the one step left, right in front of the person."""
        self.guide_wanted = True
        self.say("Your vault is created. One more step makes it much harder to crack:")


class CreateVaultPage(QWidget):
    """A new, empty vault: master password checked first, made by keepassxc-cli."""
    created = Signal(str)       # path
    back_requested = Signal()
    MIN_LENGTH = 12

    def __init__(self, runner: Runner, settings: QSettings) -> None:
        super().__init__()
        self.setObjectName("page")
        self.runner, self.settings = runner, settings
        outer = QVBoxLayout(self)
        outer.setContentsMargins(28, 20, 28, 20)
        top = QHBoxLayout()
        back = QPushButton("Back")
        back.setObjectName("link")
        back.clicked.connect(self.back_requested.emit)
        top.addWidget(back)
        top.addStretch(1)
        outer.addLayout(top)
        outer.addStretch(1)
        col = QWidget()
        col.setMaximumWidth(460)
        lay = QVBoxLayout(col)
        lay.setSpacing(10)
        title = QLabel("Create your vault")
        title.setObjectName("title")
        note = QLabel("A new, empty KeePassXC vault, kept only on this PC. Fill it by importing "
                      "your browser's passwords, or let KeePassXC save logins as you go.")
        note.setObjectName("muted")
        note.setWordWrap(True)
        lay.addWidget(title)
        lay.addWidget(note)
        lay.addSpacing(6)
        lay.addWidget(QLabel("Where to keep it"))
        row = QHBoxLayout()
        self.path = QLineEdit(str(default_vault_path()))
        browse = QPushButton("Browse…")
        browse.clicked.connect(self.browse)
        row.addWidget(self.path, 1)
        row.addWidget(browse)
        lay.addLayout(row)
        lay.addWidget(QLabel("Master password"))
        self.pw = QLineEdit()
        self.pw.setEchoMode(QLineEdit.EchoMode.Password)
        self.pw.setAccessibleName("New master password")
        self.pw.textChanged.connect(self.update_hint)
        lay.addWidget(self.pw)
        lay.addWidget(QLabel("Type it again"))
        self.pw2 = QLineEdit()
        self.pw2.setEchoMode(QLineEdit.EchoMode.Password)
        self.pw2.setAccessibleName("Repeat the master password")
        self.pw2.returnPressed.connect(self.create)
        lay.addWidget(self.pw2)
        self.hint = QLabel()
        self.hint.setObjectName("muted")
        self.hint.setWordWrap(True)
        lay.addWidget(self.hint)
        self.paper = QCheckBox("I've written it on paper and put that somewhere safe")
        lay.addWidget(self.paper)
        paper_note = QLabel("If the master password is forgotten, nobody can get the passwords "
                            "back, including vaultkit and KeePassXC.")
        paper_note.setObjectName("muted")
        paper_note.setWordWrap(True)
        lay.addWidget(paper_note)
        self.error = QLabel()
        self.error.setObjectName("error")
        self.error.setWordWrap(True)
        self.error.hide()
        lay.addWidget(self.error)
        self.go = QPushButton("Create vault")
        self.go.setObjectName("primary")
        self.go.clicked.connect(self.create)
        b = QHBoxLayout()
        b.addWidget(self.go)
        b.addStretch(1)
        lay.addSpacing(4)
        lay.addLayout(b)
        h = QHBoxLayout()
        h.addStretch(1)
        h.addWidget(col, 3)
        h.addStretch(1)
        outer.addLayout(h)
        outer.addStretch(2)
        self.update_hint()

    def reset(self, focus: bool = True) -> None:
        self.pw.clear()
        self.pw2.clear()
        self.paper.setChecked(False)
        self.error.hide()
        self.go.setEnabled(True)
        self.go.setText("Create vault")
        if not self.path.text().strip() or Path(self.path.text().strip()).exists():
            self.path.setText(str(default_vault_path()))
        if focus:
            QTimer.singleShot(0, self.pw.setFocus)

    def browse(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Where to keep your vault", self.path.text(),
                                              "KeePass databases (*.kdbx)")
        if path:
            self.path.setText(os.path.normpath(path))

    @classmethod
    def problem(cls, pw: str) -> str | None:
        if len(pw) < cls.MIN_LENGTH:
            return f"At least {cls.MIN_LENGTH} characters. Four or more random words work well."
        return strength.weakness(pw)

    def update_hint(self) -> None:
        pw = self.pw.text()
        if not pw:
            text = ("Use four or more random words, like 'maple river lantern orbit'. It's the "
                    "only password you'll need to remember.")
        else:
            text = self.problem(pw) or "Looks strong."
        self.hint.setText(text)

    def show_error(self, msg: str) -> None:
        self.error.setText(msg)
        self.error.show()

    def create(self) -> None:
        path = self.path.text().strip().strip('"')
        pw, pw2 = self.pw.text(), self.pw2.text()
        if not path:
            return self.show_error("Choose where to keep the vault.")
        if not path.lower().endswith(".kdbx"):
            path += ".kdbx"
        if Path(path).exists():
            return self.show_error("A file with that name already exists. Choose another name.")
        why = self.problem(pw)
        if why:
            return self.show_error(why)
        if pw != pw2:
            return self.show_error("The two passwords don't match.")
        if not self.paper.isChecked():
            return self.show_error("Write the master password down first, then tick the box.")
        cli = kpsetup.find_cli()
        if cli is None:
            return self.show_error("Install KeePassXC first: Back, then Setup.")
        self.pw.clear()
        self.pw2.clear()
        self.error.hide()
        self.go.setEnabled(False)
        self.go.setText("Creating…")

        def work() -> str:
            try:
                breached = vk.pwned_counts({"master": pw})
            except (OSError, urllib.error.URLError):
                breached = {}  # offline: the length and pattern checks still applied
            if breached:
                raise kpsetup.SetupError("That password appears in known data breaches. "
                                         "Choose a different one.")
            kpsetup.create_vault(cli, path, pw)
            return path

        self.runner.submit(work, self._done, self._failed)

    def _done(self, path: str) -> None:
        self.settings.setValue("db", path)
        self.go.setText("Create vault")
        self.go.setEnabled(True)
        self.created.emit(path)

    def _failed(self, msg: str) -> None:
        self.go.setText("Create vault")
        self.go.setEnabled(True)
        self.show_error(msg)
        self.pw.setFocus()


def default_vault_path() -> Path:
    """<you>\\vaultkit\\vault\\main.kdbx in the one-folder layout, else Documents."""
    folder = HERE.parent / "vault"
    base = folder if folder.is_dir() else Path.home() / "Documents"
    path, n = base / "main.kdbx", 2
    while path.exists():
        path, n = base / f"main-{n}.kdbx", n + 1
    return path


# ---------------------------------------------------------------------------- window
class Banner(QWidget):
    """One-line notice above every page: update ready, just updated, or update rejected."""

    def __init__(self) -> None:
        super().__init__()
        self.setObjectName("banner")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(28, 10, 28, 10)
        self.text = QLabel()
        self.text.setWordWrap(True)
        self.text.setTextFormat(Qt.TextFormat.PlainText)  # release notes are never HTML
        self.action = QPushButton()
        self.action.setObjectName("primary")
        self.dismiss = QPushButton("Dismiss")
        self.dismiss.setObjectName("link")
        self.dismiss.clicked.connect(self.hide)
        lay.addWidget(self.text, 1)
        lay.addWidget(self.action)
        lay.addWidget(self.dismiss)
        self.hide()

    def show_message(self, text: str, action: str = "", warn: bool = False) -> None:
        self.setProperty("warn", "true" if warn else "false")
        self.style().unpolish(self)
        self.style().polish(self)
        self.text.setText(text)
        self.action.setText(action)
        self.action.setVisible(bool(action))
        self.show()


class IdleWatcher(QObject):
    """Restart the lock timer on any keyboard or mouse activity in the app."""
    EVENTS = {QEvent.Type.KeyPress, QEvent.Type.MouseButtonPress, QEvent.Type.MouseMove,
              QEvent.Type.Wheel}

    def __init__(self, timer: QTimer) -> None:
        super().__init__()
        self.timer = timer

    def eventFilter(self, obj, event) -> bool:
        if event.type() in self.EVENTS and self.timer.isActive():
            self.timer.start()
        return False


class MainWindow(QMainWindow):
    def __init__(self, idle_minutes: float = IDLE_LOCK_MINUTES, startup_note: str = "",
                 check_updates: bool = True, background: bool = True) -> None:
        super().__init__()
        self.setWindowTitle(f"vaultkit {vk.__version__}")
        self.setWindowIcon(make_icon())
        self.quitting = False
        self.instance: InstanceServer | None = None
        self.theme_menus: list[ThemeMenu] = []
        self.notifications: list[tuple[str, str]] = []  # what was shown (tests, and no-tray PCs)
        self.setMinimumSize(720, 560)
        self.settings = QSettings("vaultkit", "vaultkit")
        self.runner = Runner()

        self.stack = QStackedWidget()
        self.unlock = UnlockPage(self.runner, self.settings)
        self.dash = DashboardPage(self.runner)
        self.clip = SecretClipboard()
        self.fix = FixPage(self.runner, self.clip)
        self.net = Runner()  # downloads and setup: never queued behind a vault check
        self.setup = SetupPage(self.net, self.settings)
        self.create = CreateVaultPage(self.runner, self.settings)
        self.setup_from: QWidget = self.unlock
        for page in (self.unlock, self.dash, self.fix, self.setup, self.create):
            self.stack.addWidget(page)
        self.banner = Banner()
        self.banner.action.clicked.connect(self.restart)

        # theme pickers: unlock screen (top right) and dashboard (top bar)
        self.theme_key = self.settings.value("theme", "system")
        unlock_menu, dash_menu = self.new_theme_menu(), self.new_theme_menu()
        row = QHBoxLayout()
        row.setContentsMargins(28, 16, 28, 0)
        row.addStretch(1)
        row.addWidget(theme_button(unlock_menu))
        self.unlock.layout().insertLayout(0, row)
        self.dash.top_bar.insertWidget(1, theme_button(dash_menu))
        self.version_labels = [version_label(), version_label()]
        foot = QHBoxLayout()
        foot.setContentsMargins(28, 0, 28, 16)
        self.setup_links = [QPushButton("Setup"), QPushButton("Setup")]
        for b in self.setup_links:
            b.setObjectName("link")
            b.setAccessibleName("Setup: install and check KeePassXC")
            b.clicked.connect(self.show_setup)
        foot.addWidget(self.setup_links[0])
        foot.addStretch(1)
        foot.addWidget(self.version_labels[0])
        self.unlock.layout().addLayout(foot)
        self.dash.top_bar.insertWidget(1, self.setup_links[1])
        self.dash.foot.addWidget(self.version_labels[1])
        hints = QApplication.styleHints()
        if hasattr(hints, "colorSchemeChanged"):
            hints.colorSchemeChanged.connect(self._system_scheme_changed)
        central = QWidget()
        col = QVBoxLayout(central)
        col.setContentsMargins(0, 0, 0, 0)
        col.setSpacing(0)
        col.addWidget(self.banner)
        col.addWidget(self.stack, 1)
        self.setCentralWidget(central)

        # updates use self.net too, so a slow download never delays a vault check
        self.update_timer = QTimer(self)
        self.update_timer.setInterval(UPDATE_CHECK_HOURS * 3600 * 1000)
        self.update_timer.timeout.connect(self.check_updates)
        if startup_note:
            warn = not startup_note.startswith("Updated")
            self.banner.show_message(startup_note, warn=warn)
        if check_updates:
            QTimer.singleShot(3000, self.check_updates)
            self.update_timer.start()

        # tray + daily background check
        self.known_breached = self._load_known_breached()
        self.tray: QSystemTrayIcon | None = None
        if QSystemTrayIcon.isSystemTrayAvailable():
            self._build_tray()
        self.daily = QTimer(self)
        self.daily.setInterval(60 * 60 * 1000)  # look hourly; runs once it's due (survives sleep)
        self.daily.timeout.connect(self.maybe_daily_check)
        if background:
            self.daily.start()
            QTimer.singleShot(90_000, self.maybe_daily_check)
        self.dash.checked.connect(lambda r: self.on_report(r, background=False))

        self.idle = QTimer(self)
        self.idle.setSingleShot(True)
        self.idle.setInterval(int(idle_minutes * 60_000))
        self.idle.timeout.connect(lambda: self.lock(
            f"Locked after {idle_minutes:g} minutes without activity."))
        self.watcher = IdleWatcher(self.idle)
        QApplication.instance().installEventFilter(self.watcher)

        self.unlock.unlocked.connect(self.on_unlocked)
        self.unlock.setup_requested.connect(self.show_setup)
        self.unlock.create_requested.connect(self.show_create)
        self.setup.back_requested.connect(self.leave_setup)
        self.setup.create_requested.connect(self.show_create)
        self.setup.autostart_requested.connect(lambda: self.set_autostart(True))
        self.create.back_requested.connect(self.leave_create)
        self.create.created.connect(self.vault_created)
        self.dash.lock_requested.connect(lambda: self.lock())
        self.dash.fix_requested.connect(self.on_fix)
        self.fix.finished.connect(self.on_fixed)

    # -- themes
    def new_theme_menu(self) -> ThemeMenu:
        menu = ThemeMenu()
        menu.sync(self.theme_key)
        menu.chosen.connect(self.set_theme)
        self.theme_menus.append(menu)
        return menu

    def set_theme(self, key: str) -> None:
        self.theme_key = key
        self.settings.setValue("theme", key)
        apply_theme(QApplication.instance(), key)
        self.refresh_theme()

    def refresh_theme(self) -> None:
        for m in self.theme_menus:
            m.sync(self.theme_key)
        for leg in (self.dash.leg_breached, self.dash.leg_risk, self.dash.leg_safe):
            leg.repaint_dot()
        self.dash.score.trend.update()
        if self.dash.report is not None:
            self.dash.show_report(self.dash.report)  # re-colour the issue swatches
        self.dash.bar.update()
        self.setup.repaint()

    def _system_scheme_changed(self, *_args) -> None:
        if self.theme_key == "system":
            self.set_theme("system")

    # -- tray
    def _build_tray(self) -> None:
        self.tray = QSystemTrayIcon(make_icon(), self)
        self.tray.setToolTip(f"vaultkit {vk.__version__}")
        menu = QMenu()
        header = menu.addAction(f"vaultkit {vk.__version__}")
        header.setEnabled(False)
        menu.addSeparator()
        open_act = menu.addAction("Open vaultkit")
        open_act.triggered.connect(self.show_window)
        check_act = menu.addAction("Check now")
        check_act.triggered.connect(lambda: self.run_check(explicit=True))
        menu.addSeparator()
        self.daily_act = QAction("Daily check", menu, checkable=True)
        self.daily_act.setChecked(self.daily_enabled)
        self.daily_act.toggled.connect(lambda on: self.settings.setValue("daily_check", on))
        menu.addAction(self.daily_act)
        self.autostart_act = QAction("Start with Windows", menu, checkable=True)
        self.autostart_act.setEnabled(autostart.supported())
        self.autostart_act.setChecked(autostart.is_enabled())
        self.autostart_act.toggled.connect(self.set_autostart)
        menu.addAction(self.autostart_act)
        menu.addMenu(self.new_theme_menu())
        menu.addSeparator()
        quit_act = menu.addAction("Quit vaultkit")
        quit_act.triggered.connect(self.quit_app)
        self.tray_menu = menu  # keep a reference: Qt doesn't own a context menu
        self.tray.setContextMenu(menu)
        self.tray.activated.connect(self._tray_activated)
        self.tray.messageClicked.connect(self.show_window)
        self.tray.show()
        autostart.refresh(HERE / "launcher.py")

    def ensure_integration(self) -> None:
        """Icon file (needs the GUI thread) then Start-menu/folder shortcuts (background)."""
        if not shortcuts.supported():
            return
        try:
            icon = write_ico(shortcuts.data_dir() / "vaultkit.ico")
        except OSError as e:
            updater.log(f"icon not written: {e}")
            return
        self.net.submit(lambda: shortcuts.ensure(HERE, icon), lambda _r: None,
                        lambda m: updater.log(f"shortcuts not updated: {m}"))

    def _tray_activated(self, reason) -> None:
        if reason in (QSystemTrayIcon.ActivationReason.Trigger,
                      QSystemTrayIcon.ActivationReason.DoubleClick):
            self.show_window()

    def set_autostart(self, on: bool) -> None:
        if on:
            autostart.enable(HERE / "launcher.py")
        else:
            autostart.disable()
        act = getattr(self, "autostart_act", None)
        if act is not None and act.isChecked() != on:
            act.blockSignals(True)
            act.setChecked(on)
            act.blockSignals(False)

    def show_window(self) -> None:
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def notify(self, title: str, body: str, warn: bool = False) -> None:
        self.notifications.append((title, body))
        if self.tray is not None:
            icon = (QSystemTrayIcon.MessageIcon.Warning if warn
                    else QSystemTrayIcon.MessageIcon.Information)
            self.tray.showMessage(title, body, icon, 15_000)

    def set_status(self, r: Report | None) -> None:
        if self.tray is None:
            return
        if r is None:
            self.tray.setIcon(make_icon())
            self.tray.setToolTip(f"vaultkit {vk.__version__}")
            return
        status = "bad" if r.breached else ("warn" if r.needs_changing else "ok")
        self.tray.setIcon(make_icon(status))
        summary = (f"score {r.score}, {r.needs_changing} need changing" if r.needs_changing
                   else f"score {r.score}, all passwords look safe")
        self.tray.setToolTip(f"vaultkit {vk.__version__}: {summary} "
                             f"(checked {r.checked_at:%a %H:%M})")

    # -- daily check
    @property
    def daily_enabled(self) -> bool:
        return self.settings.value("daily_check", True, type=bool)

    def _when(self, key: str) -> datetime | None:
        raw = self.settings.value(key, "")
        try:
            return datetime.fromisoformat(raw) if raw else None
        except ValueError:
            return None

    def check_due(self) -> bool:
        last = self._when("last_check_at")
        return last is None or datetime.now() - last >= timedelta(hours=DAILY_CHECK_HOURS)

    @staticmethod
    def _load_known_breached() -> set[str]:
        try:
            data = json.loads((vk.state_dir() / "last-check.json").read_text("utf-8"))
            return set(data.get("breached", {})) | set(data.get("site_breached", []))
        except (OSError, ValueError):
            return set()

    def maybe_daily_check(self) -> None:
        if self.daily_enabled and self.check_due():
            self.run_check(explicit=False)

    def run_check(self, explicit: bool) -> None:
        """Explicit = the person asked (tray 'Check now'): always report the result."""
        if self.dash.vault is not None and self.isVisible():
            self.show_window() if explicit else None
            self.dash.start_check()
            return
        if secretstore.supported() and secretstore.is_saved():
            self.background_check(explicit)
            return
        if explicit:
            self.show_window()
            return
        today = datetime.now().date().isoformat()
        if self.settings.value("reminded_on", "") != today:
            self.settings.setValue("reminded_on", today)
            self.notify("Daily password check", "Open vaultkit and unlock it to run today's "
                        "check. To run it automatically, tick 'Remember on this PC' when you "
                        "unlock.")

    def background_check(self, explicit: bool) -> None:
        db = self.settings.value("db", "") or os.environ.get("VAULTKIT_DB", "")
        if not db:
            if explicit:
                self.show_window()
            return
        v = vk.Vault(db=db, key_file=self.settings.value("key_file", "") or None,
                     use_saved_password=True)

        def work() -> Report:
            try:
                return run_scan(v)
            finally:
                v.lock()  # the saved password is only in memory for the length of the check

        self.runner.submit(work, lambda r: self.on_report(r, background=True, explicit=explicit),
                           lambda m: self._background_failed(m, explicit))

    def on_report(self, r: Report, background: bool, explicit: bool = False) -> None:
        self.settings.setValue("last_check_at", datetime.now().isoformat(timespec="seconds"))
        self.set_status(r)
        breached_now = {i.name for i in r.issues if i.kind == "breached"}
        new = breached_now - self.known_breached
        self.known_breached = breached_now
        if not background and self.isVisible():
            return  # they're looking at the dashboard already
        n = r.needs_changing
        if new:
            self.notify("Password found in a breach",
                        f"{len(new)} of your passwords {'was' if len(new) == 1 else 'were'} "
                        "just found in, or exposed by, a data breach. Click to change "
                        f"{'it' if len(new) == 1 else 'them'}.", warn=True)
        elif explicit:
            self.notify("Check finished",
                        f"{n} password{'s' if n != 1 else ''} need{'s' if n == 1 else ''} "
                        "changing." if n else f"All {r.scanned} passwords look safe.")
        elif n:
            last = self._when("reminded_problems_at")
            if last is None or datetime.now() - last >= timedelta(days=REMINDER_DAYS):
                self.settings.setValue("reminded_problems_at",
                                       datetime.now().isoformat(timespec="seconds"))
                self.notify("Passwords to change",
                            f"{n} password{'s' if n != 1 else ''} still need"
                            f"{'s' if n == 1 else ''} changing. Click to fix.")

    def _background_failed(self, msg: str, explicit: bool) -> None:
        updater.log(f"daily check failed: {msg}")
        today = datetime.now().date().isoformat()
        if "doesn't open this vault" in msg:
            if explicit or self.settings.value("fail_notified_on", "") != today:
                self.settings.setValue("fail_notified_on", today)
                self.notify("Daily check couldn't unlock your vault",
                            "The saved password no longer works (did the master password "
                            "change?). Open vaultkit, unlock it and tick 'Remember on this PC' "
                            "again.", warn=True)
        elif explicit:
            self.notify("Check didn't finish", msg, warn=True)
        # offline etc.: stays due, so the hourly timer simply tries again

    # -- updates
    def check_updates(self) -> None:
        current = vk.__version__
        self.net.submit(lambda: updater.check_for_update(current),
                        self._update_staged, self._update_failed)

    def _update_staged(self, staged) -> None:
        if staged is None:
            return
        notes = f" What's new: {staged.notes}" if staged.notes else ""
        self.banner.show_message(f"vaultkit {staged.version} is downloaded and verified. "
                                 f"It installs when the app restarts.{notes}", "Restart now")
        if not self.isVisible():
            self.notify("Update ready", f"vaultkit {staged.version} installs the next time "
                        "vaultkit starts. Open vaultkit and click Restart now.")

    def _update_failed(self, msg: str) -> None:
        updater.log(f"check failed: {msg}")
        if "signature" in msg or "unsafe" in msg or "doesn't match" in msg:
            self.banner.show_message(
                f"An update was rejected because it failed verification ({msg}). Nothing "
                "was installed. If you didn't publish a release just now, check your GitHub "
                "account.", warn=True)
        # offline / GitHub unreachable: stay quiet and try again tomorrow

    def restart(self) -> None:
        self.lock()
        if self.instance:
            self.instance.close()  # let the new process become the running instance
        self.quitting = True
        launcher = HERE / "launcher.py"
        subprocess.Popen([sys.executable, str(launcher)], cwd=str(HERE), close_fds=True)
        QApplication.instance().quit()

    def on_fix(self, issues: list) -> None:
        if not self.dash.vault or not self.dash.report:
            return
        self.stack.setCurrentWidget(self.fix)
        self.fix.start(self.dash.vault, issues, self.dash.report.rows)

    def on_fixed(self, changed: int) -> None:
        self.stack.setCurrentWidget(self.dash)
        self.dash.start_check()  # show the vault as it is now

    # -- setup and new vault
    def show_setup(self) -> None:
        if self.stack.currentWidget() not in (self.setup, self.create):
            self.setup_from = self.stack.currentWidget()
        self.stack.setCurrentWidget(self.setup)
        self.setup.refresh()

    def leave_setup(self) -> None:
        if self.setup_from is self.unlock or self.dash.vault is None:
            self.stack.setCurrentWidget(self.unlock)
            self.unlock.refresh()
        else:
            self.stack.setCurrentWidget(self.setup_from)

    def show_create(self) -> None:
        self.create_from = self.stack.currentWidget()
        self.create.reset()
        self.stack.setCurrentWidget(self.create)

    def leave_create(self) -> None:
        self.create.reset(focus=False)
        if getattr(self, "create_from", None) is self.setup:
            self.stack.setCurrentWidget(self.setup)
        else:
            self.stack.setCurrentWidget(self.unlock)
            self.unlock.refresh()

    def vault_created(self, path: str) -> None:
        self.create.reset(focus=False)
        self.unlock.db.setText(path)
        self.setup_from = self.unlock
        self.setup.show_vault_guide()
        self.stack.setCurrentWidget(self.setup)
        self.setup.refresh()

    def on_unlocked(self, v: vk.Vault) -> None:
        self.stack.setCurrentWidget(self.dash)
        self.idle.start()
        self.dash.open(v)

    def lock(self, message: str = "") -> None:
        self.idle.stop()
        self.fix.reset()
        self.create.reset(focus=False)  # never leave a half-typed master password on screen
        self.dash.close_vault()
        self.stack.setCurrentWidget(self.unlock)
        self.unlock.refresh(message)

    def closeEvent(self, event) -> None:
        if self.tray is not None and not self.quitting:
            # stay in the tray for the daily check, but never with the vault open
            self.lock()
            self.hide()
            event.ignore()
            if not self.settings.value("tray_hint_shown", False, type=bool):
                self.settings.setValue("tray_hint_shown", True)
                self.notify("vaultkit is still running",
                            "It's locked and in the tray by the clock, doing the daily check. "
                            "Right-click the icon to quit or turn on Start with Windows.")
            return
        self.fix.reset()
        self.dash.close_vault()
        self.runner.wait()
        self.net.wait()
        if self.tray is not None:
            self.tray.hide()
        super().closeEvent(event)

    def quit_app(self) -> None:
        self.quitting = True
        self.close()
        QApplication.instance().quit()


def system_prefers_dark() -> bool:
    hints = QApplication.styleHints()
    scheme = getattr(hints, "colorScheme", None)
    return bool(scheme) and scheme() == Qt.ColorScheme.Dark


def resolve_theme(key: str) -> Theme:
    if key == "system" or key not in THEMES:
        return THEMES["slate"] if system_prefers_dark() else THEMES["mist"]
    return THEMES[key]


def apply_theme(app: QApplication, key: str = "system") -> Theme:
    """Switch every colour in the app. Safe to call again at any time."""
    global T
    T = resolve_theme(key)
    app.setStyle("Fusion")  # consistent look; our palette, not the OS guess
    hints = app.styleHints()
    if hasattr(hints, "setColorScheme"):  # Qt 6.8+: dark/light native title bar on Windows 11
        hints.setColorScheme(Qt.ColorScheme.Dark if T.dark else Qt.ColorScheme.Light)
    pal = QPalette()
    roles = QPalette.ColorRole
    for role, colour in ((roles.Window, T.paper), (roles.WindowText, T.ink), (roles.Base, T.surface),
                         (roles.AlternateBase, T.paper), (roles.Text, T.ink),
                         (roles.Button, T.surface), (roles.ButtonText, T.ink),
                         (roles.Highlight, T.selection), (roles.HighlightedText, T.ink),
                         (roles.ToolTipBase, T.surface), (roles.ToolTipText, T.ink),
                         (roles.PlaceholderText, T.muted), (roles.Link, T.focus)):
        pal.setColor(role, QColor(colour))
    for role in (roles.WindowText, roles.Text, roles.ButtonText):
        pal.setColor(QPalette.ColorGroup.Disabled, role, QColor(T.muted))
    app.setPalette(pal)
    app.setStyleSheet(build_style(T))
    return T


def main(startup_note: str = "", start_hidden: bool = False) -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("vaultkit")
    app.setOrganizationName("vaultkit")
    if signal_running_instance(show=not start_hidden):
        return 0  # already running: it brought its window forward (or was left in the tray)
    apply_theme(app, QSettings("vaultkit", "vaultkit").value("theme", "system"))
    w = MainWindow(startup_note=startup_note)
    w.instance = InstanceServer()
    w.instance.show_requested.connect(w.show_window)
    QTimer.singleShot(1500, w.ensure_integration)
    w.resize(860, 640)
    if w.tray is not None:
        app.setQuitOnLastWindowClosed(False)
    if start_hidden and w.tray is not None:
        if startup_note:
            w.notify("vaultkit", startup_note)
    else:
        w.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
