
import sys
import hashlib
from datetime import datetime

from PySide6.QtCore import QThread, Signal, QTimer
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QComboBox,
    QTextEdit,
    QFrame,
    QHeaderView,
)

from server import get_server_status, get_suricata_alerts
from discord_alerts import send_discord_alert
import database


SERVER_USERNAME = "harsh"
SERVER_HOST = "192.168.0.195"
ALERT_LIMIT = 100
REFRESH_INTERVAL_MS = 30_000

SEVERITY_COLORS = {
    "Critical": "#f87171",
    "High": "#fb923c",
    "Medium": "#fbbf24",
    "Low": "#4ade80",
}


def convert_alert(event):
    """Convert a Suricata EVE alert into a persistent dashboard incident."""
    if not isinstance(event, dict):
        raise ValueError("Suricata alert must be a dictionary")

    alert = event.get("alert") or {}

    signature_id = alert.get("signature_id", "unknown")
    source_ip = event.get("src_ip") or "Unknown"
    source_port = event.get("src_port")
    dest_ip = event.get("dest_ip") or "Unknown"
    dest_port = event.get("dest_port")
    protocol = event.get("proto") or "Unknown"
    signature = alert.get("signature") or "Unknown Suricata alert"

    identity = (
        f"{signature_id}|{source_ip}|{source_port}|"
        f"{dest_ip}|{dest_port}|{protocol}"
    )
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:12].upper()
    incident_id = f"SN-{digest}"

    try:
        priority = int(alert.get("severity", 3))
    except (TypeError, ValueError):
        priority = 3

    if priority == 1:
        severity = "High"
    elif priority == 2:
        severity = "Medium"
    else:
        severity = "Low"

    raw_time = event.get("timestamp") or ""

    try:
        parsed_time = datetime.fromisoformat(
            raw_time.replace("Z", "+00:00")
        )
        display_time = parsed_time.strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        display_time = raw_time or datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    source = str(source_ip)
    if source_port is not None:
        source += f":{source_port}"

    destination = str(dest_ip)
    if dest_port is not None:
        destination += f":{dest_port}"

    details = (
        f"Source: {source}\n"
        f"Destination: {destination}\n"
        f"Protocol: {protocol}\n"
        f"Rule ID: {signature_id}\n"
        f"Category: {alert.get('category', 'Uncategorized')}\n"
        f"Suricata action: {alert.get('action', 'unknown')}\n\n"
        "This event was detected by Suricata. Detection alone does not "
        "prove a system was compromised. An action of 'allowed' means "
        "the traffic was not blocked by this alert."
    )

    return {
        "id": incident_id,
        "time": display_time,
        "timestamp": display_time,
        "severity": severity,
        "event": str(signature),
        "title": str(signature),
        "source": source,
        "status": "Open",
        "details": details,
        "description": details,
    }


class ServerWorker(QThread):
    result_ready = Signal(bool, str, object)

    def run(self):
        try:
            success, status_output = get_server_status(
                SERVER_USERNAME, SERVER_HOST
            )

            if not success:
                self.result_ready.emit(False, str(status_output), [])
                return

            alerts_ok, alerts_result = get_suricata_alerts(
                SERVER_USERNAME,
                SERVER_HOST,
                limit=ALERT_LIMIT,
            )

            if not alerts_ok:
                self.result_ready.emit(
                    True,
                    str(status_output) + "\nAlert retrieval failed: "
                    + str(alerts_result),
                    None,
                )
                return

            self.result_ready.emit(True, str(status_output), alerts_result)

        except Exception as exc:
            self.result_ready.emit(False, f"Unexpected sensor error: {exc}", [])


class DiscordWorker(QThread):
    finished_sending = Signal(int, int)

    def __init__(self, incidents):
        super().__init__()
        self.incidents_to_send = list(incidents)

    def run(self):
        sent = 0
        failed = 0

        for incident in self.incidents_to_send:
            try:
                success, _message = send_discord_alert(incident)
                if success:
                    sent += 1
                else:
                    failed += 1
            except Exception:
                failed += 1

        self.finished_sending.emit(sent, failed)


class SentinelNodeDashboard(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("SentinelNode | Security Operations")
        self.resize(1200, 760)
        self.setMinimumSize(900, 600)

        database.initialize_database()
        self.incidents = database.load_incidents()

        self.server_worker = None
        self.discord_worker = None
        self.notification_queue = []
        self.baseline_complete = False

        self.setStyleSheet("""
            QMainWindow, QWidget {
                background-color: #0b1120;
                color: #e5e7eb;
                font-family: Segoe UI;
                font-size: 10pt;
            }
            QLabel#title {
                font-size: 25pt;
                font-weight: bold;
                color: #f8fafc;
            }
            QLabel#muted { color: #94a3b8; }
            QLabel#sectionTitle {
                font-size: 13pt;
                font-weight: bold;
                color: #f8fafc;
            }
            QFrame#panel, QFrame#metricCard {
                background-color: #111c30;
                border: 1px solid #263449;
                border-radius: 10px;
            }
            QLabel#metricLabel { color: #94a3b8; }
            QLabel#metricValue {
                color: #f8fafc;
                font-size: 23pt;
                font-weight: bold;
            }
            QTableWidget {
                background-color: #0f172a;
                alternate-background-color: #111c30;
                color: #e5e7eb;
                gridline-color: #263449;
                border: none;
                selection-background-color: #1d4ed8;
            }
            QHeaderView::section {
                background-color: #172338;
                color: #cbd5e1;
                padding: 10px;
                border: none;
                font-weight: bold;
            }
            QComboBox, QTextEdit {
                background-color: #0f172a;
                color: #e5e7eb;
                border: 1px solid #334155;
                border-radius: 6px;
                padding: 7px;
            }
            QPushButton {
                background-color: #2563eb;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 9px 14px;
                font-weight: bold;
            }
            QPushButton:hover { background-color: #1d4ed8; }
            QPushButton:disabled {
                background-color: #334155;
                color: #94a3b8;
            }
            QPushButton#secondaryButton {
                background-color: #1e293b;
                border: 1px solid #334155;
            }
        """)

        self.build_ui()
        self.refresh_incidents()

        self.alert_timer = QTimer(self)
        self.alert_timer.setInterval(REFRESH_INTERVAL_MS)
        self.alert_timer.timeout.connect(self.check_server)
        self.alert_timer.start()

        self.check_server()

    def build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)

        main = QVBoxLayout(central)
        main.setContentsMargins(24, 20, 24, 20)
        main.setSpacing(14)

        header = QHBoxLayout()
        title_layout = QVBoxLayout()

        title = QLabel("SentinelNode")
        title.setObjectName("title")
        subtitle = QLabel("NETWORK SECURITY MONITORING")
        subtitle.setObjectName("muted")

        title_layout.addWidget(title)
        title_layout.addWidget(subtitle)
        header.addLayout(title_layout)
        header.addStretch()

        self.connection_label = QLabel("● CHECKING SERVER...")
        self.connection_label.setStyleSheet("color: #fbbf24;")
        header.addWidget(self.connection_label)
        main.addLayout(header)

        self.server_info = QLabel(
            f"Server: {SERVER_USERNAME}@{SERVER_HOST}"
        )
        self.server_info.setObjectName("muted")
        main.addWidget(self.server_info)

        metrics = QHBoxLayout()
        self.total_value = self.create_metric(metrics, "Total Incidents")
        self.high_value = self.create_metric(metrics, "High/Critical")
        self.open_value = self.create_metric(metrics, "Open Incidents")
        self.resolved_value = self.create_metric(metrics, "Resolved")
        main.addLayout(metrics)

        panel = QFrame()
        panel.setObjectName("panel")
        panel_layout = QVBoxLayout(panel)
        panel_layout.setContentsMargins(16, 16, 16, 16)

        toolbar = QHBoxLayout()
        heading = QLabel("Security Incidents")
        heading.setObjectName("sectionTitle")

        self.filter_box = QComboBox()
        self.filter_box.addItems([
            "All Severities", "Critical", "High", "Medium", "Low"
        ])
        self.filter_box.currentTextChanged.connect(self.populate_table)

        self.refresh_button = QPushButton("Refresh Alerts")
        self.refresh_button.clicked.connect(self.check_server)

        toolbar.addWidget(heading)
        toolbar.addStretch()
        toolbar.addWidget(QLabel("Severity:"))
        toolbar.addWidget(self.filter_box)
        toolbar.addWidget(self.refresh_button)
        panel_layout.addLayout(toolbar)

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels([
            "ID", "Time", "Severity", "Event", "Source", "Status"
        ])
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self.table.setSelectionMode(
            QTableWidget.SelectionMode.SingleSelection
        )
        self.table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )
        self.table.verticalHeader().setVisible(False)

        table_header = self.table.horizontalHeader()
        table_header.setSectionResizeMode(
            QHeaderView.ResizeMode.ResizeToContents
        )
        table_header.setSectionResizeMode(
            3, QHeaderView.ResizeMode.Stretch
        )
        self.table.itemSelectionChanged.connect(self.show_incident_details)

        panel_layout.addWidget(self.table)
        main.addWidget(panel, 3)

        details_panel = QFrame()
        details_panel.setObjectName("panel")
        details_layout = QVBoxLayout(details_panel)

        details_header = QHBoxLayout()
        details_title = QLabel("Incident Details")
        details_title.setObjectName("sectionTitle")

        self.resolve_button = QPushButton("Mark as Resolved")
        self.resolve_button.setObjectName("secondaryButton")
        self.resolve_button.clicked.connect(self.resolve_incident)
        self.resolve_button.setEnabled(False)

        details_header.addWidget(details_title)
        details_header.addStretch()
        details_header.addWidget(self.resolve_button)
        details_layout.addLayout(details_header)

        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setMinimumHeight(100)
        self.details_text.setPlaceholderText(
            "Select an incident to view its details."
        )
        details_layout.addWidget(self.details_text)

        main.addWidget(details_panel, 1)

        self.footer = QLabel(
            "LOCAL DATABASE | Waiting for Suricata alerts."
        )
        self.footer.setObjectName("muted")
        main.addWidget(self.footer)

    def create_metric(self, layout, label_text):
        card = QFrame()
        card.setObjectName("metricCard")
        card_layout = QVBoxLayout(card)

        label = QLabel(label_text)
        label.setObjectName("metricLabel")
        value = QLabel("0")
        value.setObjectName("metricValue")

        card_layout.addWidget(label)
        card_layout.addWidget(value)
        layout.addWidget(card)

        return value

    def refresh_incidents(self):
        self.incidents = database.load_incidents()
        self.update_summary()
        self.populate_table()

    def update_summary(self):
        self.total_value.setText(str(len(self.incidents)))
        self.high_value.setText(str(sum(
            item.get("severity") in ("High", "Critical")
            for item in self.incidents
        )))
        self.open_value.setText(str(sum(
            item.get("status") == "Open"
            for item in self.incidents
        )))
        self.resolved_value.setText(str(sum(
            item.get("status") == "Resolved"
            for item in self.incidents
        )))

    def populate_table(self, *_):
        selected_filter = self.filter_box.currentText()

        visible = [
            incident for incident in self.incidents
            if selected_filter == "All Severities"
            or incident.get("severity") == selected_filter
        ]

        self.table.setRowCount(len(visible))

        for row, incident in enumerate(visible):
            values = [
                incident.get("id", ""),
                incident.get("time", incident.get("timestamp", "")),
                incident.get("severity", "Low"),
                incident.get("event", incident.get("title", "")),
                incident.get("source", ""),
                incident.get("status", "Open"),
            ]

            for col, value in enumerate(values):
                cell = QTableWidgetItem(str(value))
                if col == 2:
                    cell.setForeground(QColor(
                        SEVERITY_COLORS.get(value, "#e5e7eb")
                    ))
                self.table.setItem(row, col, cell)

        self.table.resizeRowsToContents()

        if visible:
            self.table.selectRow(0)
        else:
            self.details_text.clear()
            self.resolve_button.setEnabled(False)

    def get_selected_incident(self):
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return None

        item = self.table.item(rows[0].row(), 0)
        if item is None:
            return None

        incident_id = item.text()
        return next(
            (incident for incident in self.incidents
             if incident.get("id") == incident_id),
            None,
        )

    def show_incident_details(self):
        incident = self.get_selected_incident()

        if incident is None:
            self.details_text.clear()
            self.resolve_button.setEnabled(False)
            return

        self.details_text.setPlainText(
            f"Incident: {incident.get('id', '')}\n"
            f"Event: {incident.get('event', incident.get('title', ''))}\n"
            f"Severity: {incident.get('severity', '')}\n"
            f"Source: {incident.get('source', '')}\n"
            f"Time: {incident.get('time', incident.get('timestamp', ''))}\n"
            f"Status: {incident.get('status', 'Open')}\n\n"
            f"{incident.get('details', incident.get('description', ''))}"
        )
        self.resolve_button.setEnabled(
            incident.get("status") == "Open"
        )

    def resolve_incident(self):
        incident = self.get_selected_incident()
        if incident is None:
            return

        updated = database.update_incident_status(
            incident["id"], "Resolved"
        )
        if not updated:
            self.footer.setText(
                "Could not update incident status in the database."
            )
            return

        self.refresh_incidents()
        self.footer.setText(
            f"{incident['id']} resolved and saved to SQLite."
        )

    def check_server(self):
        if self.server_worker and self.server_worker.isRunning():
            return

        self.refresh_button.setEnabled(False)
        self.connection_label.setText("● CHECKING SERVER...")
        self.connection_label.setStyleSheet("color: #fbbf24;")

        self.server_worker = ServerWorker()
        self.server_worker.result_ready.connect(self.server_status_received)
        self.server_worker.finished.connect(
            lambda: self.refresh_button.setEnabled(True)
        )
        self.server_worker.start()

    def server_status_received(self, success, output, alerts):
        if not success:
            self.connection_label.setText("● SERVER OFFLINE")
            self.connection_label.setStyleSheet(
                "color: #f87171; font-weight: bold;"
            )
            self.server_info.setText(
                f"Server: {SERVER_USERNAME}@{SERVER_HOST}\n{output}"
            )
            self.footer.setText(
                "SSH failed. Saved incidents remain available locally. "
                "Automatic retry will occur."
            )
            return

        self.connection_label.setText("● CYBERLAB CONNECTED")
        self.connection_label.setStyleSheet(
            "color: #4ade80; font-weight: bold;"
        )
        self.server_info.setText(
            f"Server: {SERVER_USERNAME}@{SERVER_HOST}\n{output}"
        )

        if alerts is None:
            self.footer.setText(
                "Connected, but Suricata alerts could not be retrieved. "
                "Will retry automatically."
            )
            return

        existing = {
            item["id"]: item for item in database.load_incidents()
        }
        new_notifications = []

        for event in alerts:
            incident = convert_alert(event)
            previous = existing.get(incident["id"])

            if previous:
                incident["status"] = previous.get("status", "Open")
            else:
                new_notifications.append(incident)

            database.save_incident(incident)
            existing[incident["id"]] = incident

        self.refresh_incidents()

        now = datetime.now().strftime("%H:%M:%S")
        self.footer.setText(
            f"CONNECTED | Last refresh: {now} | "
            f"Retrieved {len(alerts)} Suricata alerts. "
            f"New incidents: {len(new_notifications)}."
        )

        if new_notifications:
            self.notification_queue.extend(new_notifications)
            self.start_notification_worker()

    def start_notification_worker(self):
        if self.discord_worker and self.discord_worker.isRunning():
            return
        if not self.notification_queue:
            return

        batch = self.notification_queue[:]
        self.notification_queue.clear()

        self.discord_worker = DiscordWorker(batch)
        self.discord_worker.finished_sending.connect(
            self.discord_notifications_finished
        )
        self.discord_worker.finished.connect(
            self.start_notification_worker
        )
        self.discord_worker.start()

    def discord_notifications_finished(self, sent, failed):
        now = datetime.now().strftime("%H:%M:%S")
        self.footer.setText(
            f"Last refresh: {now} | Discord notifications sent: {sent}; "
            f"failed: {failed}."
        )


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SentinelNodeDashboard()
    window.show()
    sys.exit(app.exec())
