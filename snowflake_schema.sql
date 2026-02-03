-- Snowflake Schema for Bluetooth Attack Detection System
-- Run this script in Snowflake to create the required tables

-- Create database if not exists
CREATE DATABASE IF NOT EXISTS BT_PROTECTOR;

-- Use the database
USE DATABASE BT_PROTECTOR;

-- Create schema
CREATE SCHEMA IF NOT EXISTS PUBLIC;

USE SCHEMA PUBLIC;

-- Create devices table
CREATE OR REPLACE TABLE BT_PROTECTOR_DEVICES (
    mac_address VARCHAR(17) PRIMARY KEY,
    name VARCHAR(255),
    manufacturer VARCHAR(100),
    rssi INTEGER,
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    vulnerabilities VARIANT,
    threat_level VARCHAR(20),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP(),
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP()
);

-- Create threats table
CREATE OR REPLACE TABLE BT_PROTECTOR_THREATS (
    id INTEGER AUTOINCREMENT START 1 INCREMENT 1 PRIMARY KEY,
    timestamp TIMESTAMP,
    attack_type VARCHAR(50),
    threat_level VARCHAR(20),
    source_device VARCHAR(17),
    target_device VARCHAR(17),
    confidence FLOAT,
    description VARCHAR(500),
    details VARIANT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP()
);

-- Create detection rules table
CREATE OR REPLACE TABLE BT_PROTECTOR_DETECTION_RULES (
    rule_name VARCHAR(50) PRIMARY KEY,
    enabled BOOLEAN DEFAULT TRUE,
    threshold_value FLOAT,
    alert_level VARCHAR(20),
    description VARCHAR(255),
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP()
);

-- Create scan sessions table
CREATE OR REPLACE TABLE BT_PROTECTOR_SCAN_SESSIONS (
    id INTEGER AUTOINCREMENT START 1 INCREMENT 1 PRIMARY KEY,
    start_time TIMESTAMP,
    end_time TIMESTAMP,
    interface VARCHAR(10),
    devices_found INTEGER,
    threats_found INTEGER,
    status VARCHAR(20),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP()
);

-- Create alerts table for real-time alerts
CREATE OR REPLACE TABLE BT_PROTECTOR_ALERTS (
    id INTEGER AUTOINCREMENT START 1 INCREMENT 1 PRIMARY KEY,
    timestamp TIMESTAMP,
    alert_type VARCHAR(50),
    severity VARCHAR(20),
    source VARCHAR(255),
    message VARCHAR(500),
    acknowledged BOOLEAN DEFAULT FALSE,
    acknowledged_by VARCHAR(100),
    acknowledged_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP()
);

-- Insert default detection rules
INSERT INTO BT_PROTECTOR_DETECTION_RULES (rule_name, enabled, threshold_value, alert_level, description) VALUES
    ('knob_detection', TRUE, 7, 'CRITICAL', 'Detects Key Negotiation of Bluetooth attacks'),
    ('bias_detection', TRUE, 5, 'CRITICAL', 'Detects Bluetooth Impersonation AttackS'),
    ('braktooth_detection', TRUE, 5, 'HIGH', 'Detects BrakTooth firmware exploits'),
    ('blueborne_detection', TRUE, 500, 'CRITICAL', 'Detects BlueBorne remote code execution attempts'),
    ('pairing_flood', TRUE, 10, 'HIGH', 'Detects pairing request flooding'),
    ('rssi_anomaly', TRUE, 30, 'MEDIUM', 'Detects sudden RSSI changes'),
    ('gatt_overflow', TRUE, 512, 'HIGH', 'Detects GATT buffer overflow attempts'),
    ('device_spoofing', TRUE, NULL, 'MEDIUM', 'Detects MAC address spoofing attempts');

-- Create views for analytics
CREATE OR REPLACE VIEW BT_PROTECTOR_V_DEVICES as
SELECT 
    mac_address,
    name,
    manufacturer,
    threat_level,
    COUNT(*) as detection_count,
    MAX(last_seen) as last_seen
FROM BT_PROTECTOR_DEVICES
GROUP BY mac_address, name, manufacturer, threat_level;

CREATE OR REPLACE VIEW BT_PROTECTOR_V_THREATS as
SELECT 
    attack_type,
    threat_level,
    COUNT(*) as occurrence_count,
    AVG(confidence) as avg_confidence,
    MIN(timestamp) as first_occurrence,
    MAX(timestamp) as last_occurrence
FROM BT_PROTECTOR_THREATS
GROUP BY attack_type, threat_level;

CREATE OR REPLACE VIEW BT_PROTECTOR_V_ALERT_SUMMARY as
SELECT 
    alert_type,
    severity,
    COUNT(*) as count,
    COUNT_IF(acknowledged = TRUE) as acknowledged_count,
    COUNT_IF(acknowledged = FALSE) as pending_count
FROM BT_PROTECTOR_ALERTS
GROUP BY alert_type, severity;

-- Create stored procedure for device upsert
CREATE OR REPLACE PROCEDURE BT_PROTECTOR_SAVE_DEVICE(
    MAC_ADDRESS VARCHAR(17),
    NAME VARCHAR(255),
    MANUFACTURER VARCHAR(100),
    RSSI INTEGER,
    FIRST_SEEN TIMESTAMP,
    LAST_SEEN TIMESTAMP,
    VULNERABILITIES VARIANT,
    THREAT_LEVEL VARCHAR(20)
)
RETURNS VARCHAR
LANGUAGE SQL
AS
$$
BEGIN
    MERGE INTO BT_PROTECTOR_DEVICES AS target
    USING (SELECT :MAC_ADDRESS as mac, :NAME as name, :MANUFACTURER as manufacturer,
                  :RSSI as rssi, :FIRST_SEEN as first_seen, :LAST_SEEN as last_seen,
                  :VULNERABILITIES as vulnerabilities, :THREAT_LEVEL as threat_level) AS source
    ON target.mac_address = source.mac
    WHEN MATCHED THEN
        UPDATE SET 
            target.rssi = source.rssi,
            target.last_seen = source.last_seen,
            target.vulnerabilities = source.vulnerabilities,
            target.threat_level = source.threat_level,
            target.updated_at = CURRENT_TIMESTAMP()
    WHEN NOT MATCHED THEN
        INSERT (mac_address, name, manufacturer, rssi, first_seen, last_seen, vulnerabilities, threat_level)
        VALUES (source.mac, source.name, source.manufacturer, source.rssi, 
                source.first_seen, source.last_seen, source.vulnerabilities, source.threat_level);
    
    RETURN 'Device saved successfully';
END;
$$;

-- Create stored procedure for threat logging
CREATE OR REPLACE PROCEDURE BT_PROTECTOR_SAVE_THREAT(
    ATTACK_TIMESTAMP TIMESTAMP,
    ATTACK_TYPE VARCHAR(50),
    THREAT_LEVEL VARCHAR(20),
    SOURCE_DEVICE VARCHAR(17),
    TARGET_DEVICE VARCHAR(17),
    CONFIDENCE FLOAT,
    DESCRIPTION VARCHAR(500),
    DETAILS VARIANT
)
RETURNS VARCHAR
LANGUAGE SQL
AS
$$
BEGIN
    INSERT INTO BT_PROTECTOR_THREATS (
        timestamp, attack_type, threat_level, source_device, 
        target_device, confidence, description, details
    )
    VALUES (
        :ATTACK_TIMESTAMP, :ATTACK_TYPE, :THREAT_LEVEL, :SOURCE_DEVICE,
        :TARGET_DEVICE, :CONFIDENCE, :DESCRIPTION, :DETAILS
    );
    
    RETURN 'Threat saved successfully';
END;
$$;

-- Grant permissions (adjust as needed for your setup)
-- GRANT USAGE ON DATABASE BT_PROTECTOR TO ROLE PUBLIC;
-- GRANT USAGE ON SCHEMA PUBLIC TO ROLE PUBLIC;
-- GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA PUBLIC TO ROLE PUBLIC;

-- Show created objects
SHOW TABLES;
SHOW VIEWS;
SHOW PROCEDURES;

SELECT 'Schema creation complete!' as status;

