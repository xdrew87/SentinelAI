"""
modules/ai_assistant.py – AI-powered investigation assistant.
Supports OpenAI, Anthropic, Gemini, Ollama. Context-aware prompts,
conversation history, and pre-built DFIR analysis templates.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QVBoxLayout, QHBoxLayout, QSplitter,
    QLabel, QPushButton, QLineEdit, QTextEdit,
    QWidget, QComboBox, QListWidget, QListWidgetItem,
    QMessageBox, QFrame, QScrollArea,
)

from modules.base_module import BaseModule
from core.ai_client import AIClient

log = logging.getLogger(__name__)

_PROMPT_TEMPLATES = [
    ("Summarise Case",
     "Summarise this DFIR investigation case based on the context provided. "
     "Include key findings, attack timeline, affected systems, and recommended next steps."),
    ("Explain Alert",
     "Explain the following security alert in plain English. Include what it means, "
     "why it's significant, what an attacker could achieve, and immediate response steps:\n\n"),
    ("Map MITRE Techniques",
     "Analyse the following activity and map it to MITRE ATT&CK techniques. "
     "For each technique identified, provide: Technique ID, Name, Tactic, and why you mapped it:\n\n"),
    ("Suggest Hunt Queries",
     "Based on the following threat indicators and case context, suggest 5 proactive threat "
     "hunting queries I should run against my log data. Format each as an SQL-style query "
     "with an explanation:\n\n"),
    ("Write Incident Report",
     "Write a professional incident report based on the following case information. "
     "Include: Executive Summary, Technical Analysis, Attack Chain, Impact, and Remediation:\n\n"),
    ("Analyse IOCs",
     "Analyse the following indicators of compromise (IOCs). For each, explain: "
     "what it is, potential threat associations, and recommended defensive actions:\n\n"),
    ("Decode Payload",
     "Analyse and decode the following potentially malicious payload or command. "
     "Explain what it does step by step and identify its purpose:\n\n"),
    ("YARA Rule Generator",
     "Generate a YARA detection rule for the following malware sample characteristics or IOCs. "
     "Include proper meta fields, well-commented strings, and an accurate condition:\n\n"),
    ("Sigma Rule Generator",
     "Generate a Sigma detection rule in valid YAML format for the following threat behaviour. "
     "Include all required fields: title, description, logsource, detection, condition:\n\n"),
    ("Risk Assessment",
     "Perform a risk assessment for the following security incident. "
     "Evaluate: Likelihood, Impact, Affected Assets, Business Risk, and Priority score:\n\n"),
]

_SYSTEM_PROMPT = """You are SentinelAI, an expert AI assistant for Digital Forensics and Incident Response (DFIR),
Security Operations, and Threat Intelligence. You have deep expertise in:
- Windows/Linux forensics and memory analysis
- Network traffic analysis and protocol forensics
- Malware analysis and reverse engineering concepts
- Threat hunting and proactive detection
- MITRE ATT&CK framework mapping
- Sigma and YARA rule creation
- Incident response procedures and playbooks
- Threat intelligence analysis

Provide precise, actionable, technical responses. When analysing artefacts, be specific about
indicators and evidence. Format responses clearly with headers and bullet points where appropriate."""


class AIThread(QThread):
    chunk = Signal(str)
    finished = Signal(str)
    error = Signal(str)

    def __init__(self, client: AIClient, prompt: str, system: str,
                 provider: str, model: str) -> None:
        super().__init__()
        self._client = client
        self._prompt = prompt
        self._system = system
        self._provider = provider
        self._model = model

    def run(self) -> None:
        try:
            response = self._client.complete(
                self._prompt, system=self._system,
                provider=self._provider, model=self._model,
            )
            self.finished.emit(response)
        except Exception as exc:
            self.error.emit(str(exc))


class ChatBubble(QWidget):
    """A single chat message bubble."""

    def __init__(self, role: str, content: str, parent=None) -> None:
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 4, 0, 4)

        is_user = role == "user"
        bubble = QWidget()
        bubble.setStyleSheet(
            f"background-color: {'#1F3A5A' if is_user else '#161B22'};"
            f"border: 1px solid {'#2D5A8A' if is_user else '#30363D'};"
            f"border-radius: 8px; padding: 0px;"
        )
        bl = QVBoxLayout(bubble)
        bl.setContentsMargins(12, 8, 12, 8)
        bl.setSpacing(4)

        role_lbl = QLabel("You" if is_user else "SentinelAI")
        role_lbl.setStyleSheet(
            f"font-size: 11px; font-weight: 700; color: "
            f"{'#58A6FF' if is_user else '#3FB950'}; background: transparent;"
        )
        bl.addWidget(role_lbl)

        content_lbl = QLabel(content)
        content_lbl.setWordWrap(True)
        content_lbl.setTextInteractionFlags(
            Qt.TextSelectableByMouse | Qt.TextSelectableByKeyboard
        )
        content_lbl.setStyleSheet("background: transparent; color: #C9D1D9; font-size: 13px;")
        bl.addWidget(content_lbl)

        bubble.setMaximumWidth(820)

        if is_user:
            layout.addStretch()
            layout.addWidget(bubble)
        else:
            layout.addWidget(bubble)
            layout.addStretch()


class AIAssistantModule(BaseModule):
    """AI-powered DFIR investigation assistant."""

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        layout.addWidget(self._make_page_header(
            "AI Assistant",
            "AI-powered DFIR analyst — investigation summaries, MITRE mapping, rule generation"
        ))

        self._ai_client = AIClient(self._config)
        self._conversation: list[dict] = []
        self._ai_thread: Optional[AIThread] = None

        splitter = QSplitter(Qt.Horizontal)
        layout.addWidget(splitter, 1)

        # ── Left: prompt templates + context ──────────────────────────────
        left = QWidget()
        left.setFixedWidth(260)
        left.setStyleSheet("background-color: #161B22; border-right: 1px solid #30363D;")
        ll = QVBoxLayout(left)
        ll.setContentsMargins(10, 10, 10, 10)
        ll.setSpacing(8)

        # Provider selector
        prov_lbl = QLabel("Provider / Model")
        prov_lbl.setObjectName("Muted")
        ll.addWidget(prov_lbl)

        self._provider_combo = QComboBox()
        self._provider_combo.addItems(["openai", "anthropic", "gemini", "ollama"])
        self._provider_combo.setCurrentText(self._config.get("ai_provider", "openai"))
        ll.addWidget(self._provider_combo)

        self._model_edit = QLineEdit()
        self._model_edit.setPlaceholderText("Model name")
        self._model_edit.setText(self._config.get("ai_model", "gpt-4o"))
        ll.addWidget(self._model_edit)

        ll.addWidget(self._make_separator())

        # Context injection
        ctx_lbl = QLabel("Case Context")
        ctx_lbl.setObjectName("Muted")
        ll.addWidget(ctx_lbl)

        inject_btn = QPushButton("⬆ Inject Case Context")
        inject_btn.clicked.connect(self._inject_context)
        inject_btn.setToolTip("Prepend active case summary to next message")
        ll.addWidget(inject_btn)

        ll.addWidget(self._make_separator())

        # Templates
        tmpl_lbl = QLabel("Prompt Templates")
        tmpl_lbl.setObjectName("Muted")
        ll.addWidget(tmpl_lbl)

        self._template_list = QListWidget()
        self._template_list.setStyleSheet("font-size: 12px;")
        for name, _ in _PROMPT_TEMPLATES:
            self._template_list.addItem(name)
        self._template_list.itemDoubleClicked.connect(self._insert_template)
        ll.addWidget(self._template_list, 1)

        use_tmpl_btn = QPushButton("Use Template ▶")
        use_tmpl_btn.clicked.connect(self._insert_selected_template)
        ll.addWidget(use_tmpl_btn)

        ll.addWidget(self._make_separator())

        clear_btn = QPushButton("🗑 Clear History")
        clear_btn.clicked.connect(self._clear_history)
        ll.addWidget(clear_btn)

        splitter.addWidget(left)

        # ── Right: chat area ───────────────────────────────────────────────
        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.setSpacing(0)

        # Chat scroll area
        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setFrameShape(QFrame.NoFrame)
        self._scroll.setStyleSheet("background-color: #0D1117;")

        self._chat_container = QWidget()
        self._chat_container.setStyleSheet("background-color: #0D1117;")
        self._chat_layout = QVBoxLayout(self._chat_container)
        self._chat_layout.setContentsMargins(20, 20, 20, 20)
        self._chat_layout.setSpacing(8)
        self._chat_layout.addStretch()

        self._scroll.setWidget(self._chat_container)
        rl.addWidget(self._scroll, 1)

        # Streaming response label
        self._thinking_lbl = QLabel("")
        self._thinking_lbl.setStyleSheet(
            "color: #3FB950; font-style: italic; padding: 4px 20px; background: #0D1117;"
        )
        rl.addWidget(self._thinking_lbl)

        # Input area
        input_area = QWidget()
        input_area.setStyleSheet(
            "background-color: #161B22; border-top: 1px solid #30363D;"
        )
        ial = QVBoxLayout(input_area)
        ial.setContentsMargins(14, 10, 14, 10)
        ial.setSpacing(8)

        self._input = QTextEdit()
        self._input.setPlaceholderText(
            "Ask SentinelAI anything about this investigation…\n"
            "Shift+Enter for new line, Enter to send"
        )
        self._input.setMaximumHeight(120)
        self._input.setStyleSheet(
            "background-color: #0D1117; color: #C9D1D9; border: 1px solid #30363D; "
            "border-radius: 6px; padding: 8px; font-size: 13px;"
        )
        self._input.installEventFilter(self)
        ial.addWidget(self._input)

        btn_row = QHBoxLayout()
        self._send_btn = self._primary_btn("Send ↵")
        self._send_btn.clicked.connect(self._send)
        self._send_btn.setFixedWidth(100)
        self._char_count = QLabel("0")
        self._char_count.setObjectName("Muted")
        self._input.textChanged.connect(
            lambda: self._char_count.setText(str(len(self._input.toPlainText())))
        )
        btn_row.addStretch()
        btn_row.addWidget(self._char_count)
        btn_row.addWidget(QLabel("chars"))
        btn_row.addWidget(self._send_btn)
        ial.addLayout(btn_row)

        rl.addWidget(input_area)
        splitter.addWidget(right)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)

        # Welcome message
        self._add_bubble("assistant",
            "Hello! I'm SentinelAI, your AI-powered DFIR assistant. "
            "I can help you analyse evidence, map MITRE techniques, explain alerts, "
            "generate YARA/Sigma rules, and produce investigation reports.\n\n"
            "Select a case and use the prompt templates on the left to get started, "
            "or just ask me anything about your investigation.")

    # ── Event filter for Enter key ──────────────────────────────────────────

    def eventFilter(self, obj, event) -> bool:
        from PySide6.QtCore import QEvent
        from PySide6.QtGui import QKeyEvent
        if obj is self._input and event.type() == QEvent.KeyPress:
            key_event = QKeyEvent(event)
            if key_event.key() == Qt.Key_Return and not (key_event.modifiers() & Qt.ShiftModifier):
                self._send()
                return True
        return super().eventFilter(obj, event)

    # ── Chat operations ────────────────────────────────────────────────────

    def _send(self) -> None:
        text = self._input.toPlainText().strip()
        if not text:
            return
        if self._ai_thread and self._ai_thread.isRunning():
            QMessageBox.information(self, "Busy", "Waiting for AI response…")
            return

        self._input.clear()
        self._add_bubble("user", text)
        self._thinking_lbl.setText("SentinelAI is thinking…")
        self._send_btn.setEnabled(False)

        provider = self._provider_combo.currentText()
        model = self._model_edit.text().strip() or self._config.get("ai_model", "gpt-4o")

        # Build full prompt with conversation context (last 10 exchanges)
        history_parts = []
        for msg in self._conversation[-20:]:
            role_prefix = "User" if msg["role"] == "user" else "Assistant"
            history_parts.append(f"{role_prefix}: {msg['content']}")
        history_text = "\n\n".join(history_parts)
        full_prompt = f"{history_text}\n\nUser: {text}" if history_text else text

        self._conversation.append({"role": "user", "content": text})

        self._ai_thread = AIThread(
            self._ai_client, full_prompt, _SYSTEM_PROMPT, provider, model
        )
        self._ai_thread.finished.connect(self._on_response)
        self._ai_thread.error.connect(self._on_error)
        self._ai_thread.start()

    def _on_response(self, response: str) -> None:
        self._thinking_lbl.setText("")
        self._send_btn.setEnabled(True)
        self._conversation.append({"role": "assistant", "content": response})
        self._add_bubble("assistant", response)

        # Persist to DB
        provider = self._provider_combo.currentText()
        model = self._model_edit.text().strip()
        if len(self._conversation) >= 2:
            last_user = self._conversation[-2]["content"]
            self._db.insert(
                """INSERT INTO ai_conversations
                   (case_id, provider, model, prompt, response)
                   VALUES (?,?,?,?,?)""",
                (self._active_case_id, provider, model, last_user[:4000], response[:8000]),
            )

    def _on_error(self, msg: str) -> None:
        self._thinking_lbl.setText("")
        self._send_btn.setEnabled(True)
        self._add_bubble(
            "assistant",
            f"⚠ Error connecting to AI provider: {msg}\n\n"
            f"Please check your API key in Settings → AI & Integrations."
        )

    def _add_bubble(self, role: str, content: str) -> None:
        bubble = ChatBubble(role, content)
        # Insert before the stretch item at the end
        count = self._chat_layout.count()
        self._chat_layout.insertWidget(count - 1, bubble)
        # Scroll to bottom
        from PySide6.QtCore import QTimer
        QTimer.singleShot(50, lambda: self._scroll.verticalScrollBar().setValue(
            self._scroll.verticalScrollBar().maximum()
        ))

    def _clear_history(self) -> None:
        self._conversation.clear()
        # Remove all bubbles except the stretch
        while self._chat_layout.count() > 1:
            item = self._chat_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

    # ── Templates ──────────────────────────────────────────────────────────

    def _insert_template(self, item: QListWidgetItem) -> None:
        name = item.text()
        template = next((t for n, t in _PROMPT_TEMPLATES if n == name), "")
        if template:
            self._input.setPlainText(template)
            self._input.setFocus()

    def _insert_selected_template(self) -> None:
        item = self._template_list.currentItem()
        if item:
            self._insert_template(item)

    def _inject_context(self) -> None:
        if not self._active_case_id:
            QMessageBox.warning(self, "No Case", "Activate a case first.")
            return
        case = self._db.fetchone("SELECT * FROM cases WHERE id=?", (self._active_case_id,))
        if not case:
            return
        _r1 = self._db.fetchone("SELECT COUNT(*) AS c FROM log_events WHERE case_id=?", (self._active_case_id,))
        ev_count = _r1["c"] if _r1 else 0
        _r2 = self._db.fetchone("SELECT COUNT(*) AS c FROM iocs WHERE case_id=?", (self._active_case_id,))
        ioc_count = _r2["c"] if _r2 else 0
        iocs = self._db.fetchall(
            "SELECT ioc_type, value FROM iocs WHERE case_id=? LIMIT 20",
            (self._active_case_id,)
        )
        ioc_list = "\n".join(f"  - [{r['ioc_type']}] {r['value']}" for r in iocs)
        context = (
            f"=== CASE CONTEXT ===\n"
            f"Case: {case['title']}\n"
            f"Severity: {case['severity'].upper()}\n"
            f"Status: {case['status']}\n"
            f"Analyst: {case.get('analyst','')}\n"
            f"Description: {case.get('description','')}\n"
            f"Log Events: {ev_count:,}\n"
            f"IOCs ({ioc_count}):\n{ioc_list}\n"
            f"===================\n\n"
        )
        current = self._input.toPlainText()
        self._input.setPlainText(context + current)
        self._input.setFocus()

    def _on_case_changed(self, case_id) -> None:
        pass
