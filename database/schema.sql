-- Website Security & Threat Intelligence Analyzer Database Schema

CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    target_url TEXT NOT NULL,
    domain TEXT NOT NULL,
    ip_address TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status TEXT NOT NULL DEFAULT 'completed',
    risk_score INTEGER NOT NULL DEFAULT 100,
    risk_grade TEXT NOT NULL DEFAULT 'A',
    critical_count INTEGER NOT NULL DEFAULT 0,
    high_count INTEGER NOT NULL DEFAULT 0,
    medium_count INTEGER NOT NULL DEFAULT 0,
    low_count INTEGER NOT NULL DEFAULT 0,
    info_count INTEGER NOT NULL DEFAULT 0,
    total_findings INTEGER NOT NULL DEFAULT 0,
    port_scan_enabled INTEGER NOT NULL DEFAULT 0,
    threat_intel_status TEXT DEFAULT 'Not Checked',
    scan_duration_seconds REAL DEFAULT 0.0,
    error_message TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    evidence TEXT,
    explanation TEXT,
    remediation TEXT,
    confidence TEXT DEFAULT 'High',
    FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS recon_data (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL UNIQUE,
    http_status INTEGER,
    https_enabled INTEGER,
    page_title TEXT,
    server_header TEXT,
    redirect_chain_json TEXT,
    dns_records_json TEXT,
    tls_cert_json TEXT,
    technologies_json TEXT,
    open_ports_json TEXT,
    threat_intel_json TEXT,
    ai_explanation TEXT,
    FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_recon_scan_id ON recon_data(scan_id);
