import sqlite3
import json
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'trust_advisor.db')


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            dark_pattern_score REAL DEFAULT 0,
            phishing_score REAL DEFAULT 0,
            ai_risk_score REAL DEFAULT 0,
            total_score REAL DEFAULT 0,
            risk_level TEXT DEFAULT 'LOW',
            verdict TEXT DEFAULT 'SAFE',
            verdict_message TEXT DEFAULT '',
            dark_indicators TEXT DEFAULT '[]',
            phishing_indicators TEXT DEFAULT '[]',
            ai_indicators TEXT DEFAULT '[]',
            screenshot_path TEXT DEFAULT '',
            report_path TEXT DEFAULT '',
            scan_status TEXT DEFAULT 'complete',
            status_message TEXT DEFAULT '',
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()


def save_scan(data: dict) -> int:
    conn = get_connection()
    c = conn.cursor()
    c.execute('''
        INSERT INTO scans (
            url, dark_pattern_score, phishing_score, ai_risk_score,
            total_score, risk_level, verdict, verdict_message,
            dark_indicators, phishing_indicators, ai_indicators,
            screenshot_path, report_path, scan_status, status_message, timestamp
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        data.get('url', ''),
        data.get('dark_pattern_score', 0),
        data.get('phishing_score', 0),
        data.get('ai_risk_score', 0),
        data.get('total_score', 0),
        data.get('risk_level', 'LOW'),
        data.get('verdict', 'SAFE'),
        data.get('verdict_message', ''),
        json.dumps(data.get('dark_indicators', [])),
        json.dumps(data.get('phishing_indicators', [])),
        json.dumps(data.get('ai_indicators', [])),
        data.get('screenshot_path', ''),
        data.get('report_path', ''),
        data.get('scan_status', 'complete'),
        data.get('status_message', ''),
        datetime.utcnow().isoformat()
    ))
    conn.commit()
    scan_id = c.lastrowid
    conn.close()
    return scan_id


def get_scan(scan_id: int) -> dict:
    conn = get_connection()
    c = conn.cursor()
    c.execute('SELECT * FROM scans WHERE id = ?', (scan_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return {}
    d = dict(row)
    d['dark_indicators'] = json.loads(d.get('dark_indicators') or '[]')
    d['phishing_indicators'] = json.loads(d.get('phishing_indicators') or '[]')
    d['ai_indicators'] = json.loads(d.get('ai_indicators') or '[]')
    return d


def get_all_scans(limit: int = 50) -> list:
    conn = get_connection()
    c = conn.cursor()
    c.execute('SELECT * FROM scans ORDER BY timestamp DESC LIMIT ?', (limit,))
    rows = c.fetchall()
    conn.close()
    result = []
    for row in rows:
        d = dict(row)
        d['dark_indicators'] = json.loads(d.get('dark_indicators') or '[]')
        d['phishing_indicators'] = json.loads(d.get('phishing_indicators') or '[]')
        d['ai_indicators'] = json.loads(d.get('ai_indicators') or '[]')
        result.append(d)
    return result


def update_report_path(scan_id: int, path: str):
    conn = get_connection()
    c = conn.cursor()
    c.execute('UPDATE scans SET report_path = ? WHERE id = ?', (path, scan_id))
    conn.commit()
    conn.close()