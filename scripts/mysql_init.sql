-- MySQL 8 Initialization Script for MCP-Guard Integration Tests
-- Sets up an isolated test database, populates schema and synthetic data,
-- and provisions a dedicated read-only user for mcp-guard query execution.

CREATE DATABASE IF NOT EXISTS mcp_guard_test;
USE mcp_guard_test;

-- Provision read-only user (for principle of least privilege)
CREATE USER IF NOT EXISTS 'mcp_readonly'@'%' IDENTIFIED BY 'ReadOnlySecretPass2026!';
GRANT SELECT ON mcp_guard_test.* TO 'mcp_readonly'@'%';
FLUSH PRIVILEGES;

-- Also create an admin user for initial migrations in test runners
CREATE USER IF NOT EXISTS 'mcp_admin'@'%' IDENTIFIED BY 'AdminSecretPass2026!';
GRANT ALL PRIVILEGES ON mcp_guard_test.* TO 'mcp_admin'@'%';
FLUSH PRIVILEGES;

-- Schema definitions
CREATE TABLE IF NOT EXISTS customers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    full_name VARCHAR(120) NOT NULL,
    email VARCHAR(160) NOT NULL,
    phone VARCHAR(32) NOT NULL,
    address VARCHAR(255) NOT NULL,
    credit_card_last4 VARCHAR(4) NOT NULL,
    ssn_last4 VARCHAR(4) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    sku VARCHAR(32) NOT NULL UNIQUE,
    name VARCHAR(120) NOT NULL,
    category VARCHAR(64) NOT NULL,
    price_cents INT NOT NULL,
    stock_quantity INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS orders (
    id INT AUTO_INCREMENT PRIMARY KEY,
    customer_id INT NOT NULL,
    order_status VARCHAR(32) NOT NULL,
    total_cents INT NOT NULL,
    shipping_address VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS order_items (
    id INT AUTO_INCREMENT PRIMARY KEY,
    order_id INT NOT NULL,
    product_id INT NOT NULL,
    quantity INT NOT NULL,
    unit_price_cents INT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS audit_records (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp VARCHAR(64) NOT NULL,
    agent_id VARCHAR(64) NOT NULL,
    tool_name VARCHAR(64) NOT NULL,
    original_sql TEXT NOT NULL,
    rewritten_sql TEXT NOT NULL,
    decision VARCHAR(32) NOT NULL,
    row_count INT NOT NULL,
    prev_hash VARCHAR(64) NOT NULL,
    record_hash VARCHAR(64) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS agent_keys (
    agent_id VARCHAR(64) PRIMARY KEY,
    token_hash VARCHAR(128) NOT NULL,
    description VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    revoked TINYINT(1) DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Populate deterministic synthetic seed data
INSERT INTO customers (id, full_name, email, phone, address, credit_card_last4, ssn_last4, created_at) VALUES
(1, 'Alice Vance', 'alice.vance@example.corp', '+1-555-0101', '101 Cyber Way, Silicon Valley, CA 94025', '4321', '6789', '2026-01-15 10:30:00'),
(2, 'Bob Mercer', 'bob.mercer@testmail.org', '+1-555-0102', '202 Harbor Blvd, Boston, MA 02110', '8765', '1234', '2026-02-10 14:15:00'),
(3, 'Carol Danvers', 'carol.danvers@demo.net', '+1-555-0103', '303 Summit Ave, Seattle, WA 98101', '9012', '4567', '2026-03-01 09:00:00'),
(4, 'David Zhao', 'david.zhao@synthetic.io', '+1-555-0104', '404 Pine St, Austin, TX 78701', '3456', '7890', '2026-03-12 11:45:00'),
(5, 'Elena Rostova', 'elena.rostova@mockidentity.dev', '+1-555-0105', '505 Oak Lane, Denver, CO 80202', '7890', '2345', '2026-04-05 16:20:00')
ON DUPLICATE KEY UPDATE full_name=VALUES(full_name);

INSERT INTO products (id, sku, name, category, price_cents, stock_quantity, created_at) VALUES
(1, 'SKU-SEC-001', 'Hardware Security Key FIDO2', 'Security', 4500, 150, '2026-01-01 00:00:00'),
(2, 'SKU-SEC-002', 'Encrypted NVMe SSD 1TB', 'Hardware', 12900, 75, '2026-01-02 00:00:00'),
(3, 'SKU-NET-003', 'Managed Gigabit Switch 24-Port', 'Networking', 24900, 30, '2026-01-05 00:00:00'),
(4, 'SKU-SFT-004', 'Static Analysis Suite License', 'Software', 49900, 500, '2026-01-10 00:00:00'),
(5, 'SKU-ACC-005', 'Shielded Cat6A Patch Cable 10ft', 'Accessories', 1200, 600, '2026-01-12 00:00:00')
ON DUPLICATE KEY UPDATE name=VALUES(name);

INSERT INTO agent_keys (agent_id, token_hash, description, created_at, revoked) VALUES
('analytics-agent', 'abe45dda0e4814a9f423e743a1ea2737358dca2a0e9dde84c725b0c81466667c', 'Read-only analytics agent with PII masking', '2026-01-01 00:00:00', 0),
('support-agent', 'ea6675ffc82c9a534c69810570f52f3f55402e7dce64da367dbf5fb55be45009', 'Customer support tier 1 agent', '2026-01-01 00:00:00', 0),
('restricted-agent', 'f107c6d6c044b2ec0e279b14a0dd59e425238ddeb3b0fdaceea363816edc7a97', 'Restricted catalog agent', '2026-01-01 00:00:00', 0),
('revoked-agent', '970ba8b48254f95fb325cac3ea83db3e2bbdbbc2253eae58590dcd3f8c9074b5', 'Decommissioned test agent', '2026-01-01 00:00:00', 1)
ON DUPLICATE KEY UPDATE description=VALUES(description);
