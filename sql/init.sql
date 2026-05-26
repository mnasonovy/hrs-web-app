CREATE TABLE IF NOT EXISTS incidents (
    id SERIAL PRIMARY KEY,
    title VARCHAR(150) NOT NULL,
    severity VARCHAR(20) NOT NULL DEFAULT 'medium',
    status VARCHAR(30) NOT NULL DEFAULT 'open',
    source_ip VARCHAR(45),
    assignee VARCHAR(80) DEFAULT 'HRS SOC',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE incidents
ADD COLUMN IF NOT EXISTS source_ip VARCHAR(45);

ALTER TABLE incidents
ADD COLUMN IF NOT EXISTS assignee VARCHAR(80) DEFAULT 'HRS SOC';

ALTER TABLE incidents
ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;

INSERT INTO incidents (title, severity, status, source_ip, assignee)
SELECT 'Suspicious SSH login attempt', 'medium', 'open', '10.10.20.15', 'SOC Analyst'
WHERE NOT EXISTS (
    SELECT 1 FROM incidents WHERE title = 'Suspicious SSH login attempt'
);

INSERT INTO incidents (title, severity, status, source_ip, assignee)
SELECT 'Multiple failed authentication attempts', 'high', 'investigating', '192.168.0.44', 'Security Admin'
WHERE NOT EXISTS (
    SELECT 1 FROM incidents WHERE title = 'Multiple failed authentication attempts'
);

INSERT INTO incidents (title, severity, status, source_ip, assignee)
SELECT 'Potential brute-force activity detected', 'critical', 'open', '100.77.220.77', 'HRS SOC'
WHERE NOT EXISTS (
    SELECT 1 FROM incidents WHERE title = 'Potential brute-force activity detected'
);
