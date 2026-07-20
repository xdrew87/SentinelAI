"""
ui/theme.py – SentinelAI dark theme stylesheet for PySide6.

Palette:
  Background canvas  #0D1117   (GitHub dark surface)
  Panel / widget     #161B22   (slightly lighter panel)
  Border             #30363D
  Accent blue        #58A6FF
  Accent cyan        #39D353
  Text primary       #C9D1D9
  Text muted         #8B949E
  Critical red       #F85149
  Warning orange     #D29922
  Success green      #3FB950
"""

STYLESHEET = """
/* ── Global ─────────────────────────────────────────────────────────────── */
QWidget {
    background-color: #0D1117;
    color: #C9D1D9;
    font-family: "Segoe UI", "SF Pro Display", "Inter", "Ubuntu", sans-serif;
    font-size: 13px;
}

/* ── Main window / frames ────────────────────────────────────────────────── */
QMainWindow, QDialog {
    background-color: #0D1117;
}

QFrame {
    background-color: transparent;
}

QFrame[frameShape="4"],   /* HLine */
QFrame[frameShape="5"] {  /* VLine */
    color: #30363D;
    background-color: #30363D;
}

/* ── Sidebar / nav panel ─────────────────────────────────────────────────── */
QListWidget#NavList {
    background-color: #161B22;
    border: none;
    border-right: 1px solid #30363D;
    padding: 8px 0;
    font-size: 13px;
    color: #8B949E;
}

QListWidget#NavList::item {
    padding: 10px 20px;
    border-radius: 0px;
    color: #8B949E;
}

QListWidget#NavList::item:hover {
    background-color: #21262D;
    color: #C9D1D9;
}

QListWidget#NavList::item:selected {
    background-color: #1F3A5A;
    color: #58A6FF;
    border-left: 3px solid #58A6FF;
    font-weight: 600;
}

/* ── Stacked / tab areas ─────────────────────────────────────────────────── */
QStackedWidget {
    background-color: #0D1117;
}

/* ── Buttons ─────────────────────────────────────────────────────────────── */
QPushButton {
    background-color: #21262D;
    color: #C9D1D9;
    border: 1px solid #30363D;
    border-radius: 6px;
    padding: 6px 16px;
    font-size: 13px;
    font-weight: 500;
}

QPushButton:hover {
    background-color: #30363D;
    border-color: #58A6FF;
}

QPushButton:pressed {
    background-color: #1F3A5A;
}

QPushButton:disabled {
    color: #484F58;
    border-color: #21262D;
}

QPushButton#PrimaryButton {
    background-color: #1F6FEB;
    color: #FFFFFF;
    border-color: #1F6FEB;
    font-weight: 600;
}

QPushButton#PrimaryButton:hover {
    background-color: #388BFD;
    border-color: #388BFD;
}

QPushButton#DangerButton {
    background-color: #B91C1C;
    color: #FFFFFF;
    border-color: #B91C1C;
}

QPushButton#DangerButton:hover {
    background-color: #DC2626;
}

/* ── Input fields ────────────────────────────────────────────────────────── */
QLineEdit, QTextEdit, QPlainTextEdit {
    background-color: #161B22;
    color: #C9D1D9;
    border: 1px solid #30363D;
    border-radius: 6px;
    padding: 6px 10px;
    selection-background-color: #1F3A5A;
    selection-color: #C9D1D9;
}

QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus {
    border-color: #58A6FF;
}

QLineEdit:read-only {
    background-color: #0D1117;
    color: #8B949E;
}

/* ── ComboBox ────────────────────────────────────────────────────────────── */
QComboBox {
    background-color: #161B22;
    color: #C9D1D9;
    border: 1px solid #30363D;
    border-radius: 6px;
    padding: 5px 10px;
    min-width: 120px;
}

QComboBox:hover { border-color: #58A6FF; }

QComboBox::drop-down {
    border: none;
    width: 24px;
}

QComboBox::down-arrow {
    image: none;
    border-left: 4px solid transparent;
    border-right: 4px solid transparent;
    border-top: 6px solid #8B949E;
    margin-right: 6px;
}

QComboBox QAbstractItemView {
    background-color: #161B22;
    color: #C9D1D9;
    border: 1px solid #30363D;
    selection-background-color: #1F3A5A;
    outline: none;
}

/* ── Spin boxes ──────────────────────────────────────────────────────────── */
QSpinBox, QDoubleSpinBox {
    background-color: #161B22;
    color: #C9D1D9;
    border: 1px solid #30363D;
    border-radius: 6px;
    padding: 5px 8px;
}

/* ── Tables ──────────────────────────────────────────────────────────────── */
QTableWidget, QTableView {
    background-color: #0D1117;
    color: #C9D1D9;
    gridline-color: #21262D;
    border: 1px solid #30363D;
    border-radius: 4px;
    alternate-background-color: #161B22;
}

QTableWidget::item, QTableView::item {
    padding: 4px 8px;
    border: none;
}

QTableWidget::item:selected, QTableView::item:selected {
    background-color: #1F3A5A;
    color: #C9D1D9;
}

QHeaderView::section {
    background-color: #161B22;
    color: #8B949E;
    border: none;
    border-right: 1px solid #30363D;
    border-bottom: 1px solid #30363D;
    padding: 6px 10px;
    font-weight: 600;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

QHeaderView::section:hover {
    background-color: #21262D;
    color: #C9D1D9;
}

/* ── Tree widgets ────────────────────────────────────────────────────────── */
QTreeWidget, QTreeView {
    background-color: #0D1117;
    color: #C9D1D9;
    border: 1px solid #30363D;
    alternate-background-color: #161B22;
}

QTreeWidget::item:selected, QTreeView::item:selected {
    background-color: #1F3A5A;
}

/* ── Splitter ────────────────────────────────────────────────────────────── */
QSplitter::handle {
    background-color: #30363D;
    width: 2px;
    height: 2px;
}

/* ── Tab bar ─────────────────────────────────────────────────────────────── */
QTabWidget::pane {
    border: 1px solid #30363D;
    border-radius: 4px;
    background-color: #0D1117;
}

QTabBar::tab {
    background-color: #161B22;
    color: #8B949E;
    border: 1px solid #30363D;
    border-bottom: none;
    padding: 8px 18px;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
    margin-right: 2px;
}

QTabBar::tab:selected {
    background-color: #0D1117;
    color: #58A6FF;
    border-color: #30363D;
    border-bottom: 2px solid #58A6FF;
    font-weight: 600;
}

QTabBar::tab:hover {
    background-color: #21262D;
    color: #C9D1D9;
}

/* ── Scroll bars ─────────────────────────────────────────────────────────── */
QScrollBar:vertical {
    background-color: #0D1117;
    width: 8px;
    border: none;
}

QScrollBar::handle:vertical {
    background-color: #30363D;
    border-radius: 4px;
    min-height: 24px;
}

QScrollBar::handle:vertical:hover {
    background-color: #484F58;
}

QScrollBar:horizontal {
    background-color: #0D1117;
    height: 8px;
    border: none;
}

QScrollBar::handle:horizontal {
    background-color: #30363D;
    border-radius: 4px;
    min-width: 24px;
}

QScrollBar::add-line, QScrollBar::sub-line { width: 0; height: 0; }
QScrollBar::add-page, QScrollBar::sub-page { background: none; }

/* ── Labels ──────────────────────────────────────────────────────────────── */
QLabel {
    background: transparent;
    color: #C9D1D9;
}

QLabel#SectionTitle {
    font-size: 15px;
    font-weight: 700;
    color: #C9D1D9;
    padding: 8px 0 4px 0;
}

QLabel#Muted {
    color: #8B949E;
    font-size: 12px;
}

QLabel#AccentLabel {
    color: #58A6FF;
    font-weight: 600;
}

QLabel#CriticalLabel {
    color: #F85149;
    font-weight: 600;
}

QLabel#SuccessLabel {
    color: #3FB950;
    font-weight: 600;
}

QLabel#WarningLabel {
    color: #D29922;
    font-weight: 600;
}

/* ── Group boxes ─────────────────────────────────────────────────────────── */
QGroupBox {
    border: 1px solid #30363D;
    border-radius: 6px;
    margin-top: 1.2em;
    padding: 12px 8px 8px 8px;
    color: #8B949E;
    font-weight: 600;
    font-size: 12px;
    text-transform: uppercase;
}

QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 0 8px;
    color: #58A6FF;
    left: 12px;
}

/* ── Status bar ──────────────────────────────────────────────────────────── */
QStatusBar {
    background-color: #161B22;
    color: #8B949E;
    border-top: 1px solid #30363D;
    font-size: 12px;
    padding: 2px 8px;
}

QStatusBar::item { border: none; }

/* ── Menu ────────────────────────────────────────────────────────────────── */
QMenuBar {
    background-color: #161B22;
    color: #C9D1D9;
    border-bottom: 1px solid #30363D;
}

QMenuBar::item:selected {
    background-color: #21262D;
}

QMenu {
    background-color: #161B22;
    color: #C9D1D9;
    border: 1px solid #30363D;
    border-radius: 4px;
}

QMenu::item:selected {
    background-color: #1F3A5A;
    color: #58A6FF;
}

QMenu::separator {
    height: 1px;
    background-color: #30363D;
    margin: 4px 8px;
}

/* ── Checkboxes / radio ──────────────────────────────────────────────────── */
QCheckBox {
    color: #C9D1D9;
    spacing: 8px;
}

QCheckBox::indicator {
    width: 16px;
    height: 16px;
    border: 1px solid #30363D;
    border-radius: 3px;
    background-color: #161B22;
}

QCheckBox::indicator:checked {
    background-color: #1F6FEB;
    border-color: #1F6FEB;
}

QRadioButton {
    color: #C9D1D9;
    spacing: 8px;
}

QRadioButton::indicator {
    width: 14px;
    height: 14px;
    border-radius: 7px;
    border: 1px solid #30363D;
    background-color: #161B22;
}

QRadioButton::indicator:checked {
    background-color: #1F6FEB;
    border-color: #1F6FEB;
}

/* ── Progress bar ────────────────────────────────────────────────────────── */
QProgressBar {
    background-color: #21262D;
    border: 1px solid #30363D;
    border-radius: 4px;
    height: 8px;
    text-align: center;
    color: transparent;
}

QProgressBar::chunk {
    background-color: #1F6FEB;
    border-radius: 4px;
}

/* ── Tooltips ────────────────────────────────────────────────────────────── */
QToolTip {
    background-color: #1C2128;
    color: #C9D1D9;
    border: 1px solid #30363D;
    border-radius: 4px;
    padding: 4px 8px;
    font-size: 12px;
}

/* ── Sliders ─────────────────────────────────────────────────────────────── */
QSlider::groove:horizontal {
    background-color: #21262D;
    height: 4px;
    border-radius: 2px;
}

QSlider::handle:horizontal {
    background-color: #1F6FEB;
    width: 14px;
    height: 14px;
    border-radius: 7px;
    margin: -5px 0;
}

/* ── Dock widgets ────────────────────────────────────────────────────────── */
QDockWidget {
    color: #C9D1D9;
    titlebar-close-icon: none;
}

QDockWidget::title {
    background-color: #161B22;
    border-bottom: 1px solid #30363D;
    padding: 6px 12px;
    font-weight: 600;
    font-size: 12px;
    color: #8B949E;
    text-transform: uppercase;
}

/* ── Severity badge labels ───────────────────────────────────────────────── */
QLabel#BadgeCritical {
    background-color: #F85149;
    color: #FFFFFF;
    border-radius: 4px;
    padding: 2px 8px;
    font-weight: 700;
    font-size: 11px;
}

QLabel#BadgeHigh {
    background-color: #D29922;
    color: #FFFFFF;
    border-radius: 4px;
    padding: 2px 8px;
    font-weight: 700;
    font-size: 11px;
}

QLabel#BadgeMedium {
    background-color: #1F6FEB;
    color: #FFFFFF;
    border-radius: 4px;
    padding: 2px 8px;
    font-weight: 700;
    font-size: 11px;
}

QLabel#BadgeLow {
    background-color: #3FB950;
    color: #FFFFFF;
    border-radius: 4px;
    padding: 2px 8px;
    font-weight: 700;
    font-size: 11px;
}
"""


def apply_theme(app) -> None:
    """Apply the SentinelAI dark theme to the QApplication."""
    app.setStyleSheet(STYLESHEET)
