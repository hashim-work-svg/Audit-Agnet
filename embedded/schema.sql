-- Database Schema for MCP-Guard
-- Compatible with both SQLite and MySQL 8.0

CREATE TABLE IF NOT EXISTS customers (
    id INTEGER PRIMARY KEY,
    full_name VARCHAR(120) NOT NULL,
    email VARCHAR(160) NOT NULL,
    phone VARCHAR(32) NOT NULL,
    address VARCHAR(255) NOT NULL,
    credit_card_last4 VARCHAR(4) NOT NULL,
    ssn_last4 VARCHAR(4) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY,
    sku VARCHAR(32) NOT NULL UNIQUE,
    name VARCHAR(120) NOT NULL,
    category VARCHAR(64) NOT NULL,
    price_cents INTEGER NOT NULL,
    stock_quantity INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY,
    customer_id INTEGER NOT NULL,
    order_status VARCHAR(32) NOT NULL,
    total_cents INTEGER NOT NULL,
    shipping_address VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS order_items (
    id INTEGER PRIMARY KEY,
    order_id INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    quantity INTEGER NOT NULL,
    unit_price_cents INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_records (
    id INTEGER PRIMARY KEY,
    timestamp VARCHAR(64) NOT NULL,
    agent_id VARCHAR(64) NOT NULL,
    tool_name VARCHAR(64) NOT NULL,
    original_sql TEXT NOT NULL,
    rewritten_sql TEXT NOT NULL,
    decision VARCHAR(32) NOT NULL,
    row_count INTEGER NOT NULL,
    prev_hash VARCHAR(64) NOT NULL,
    record_hash VARCHAR(64) NOT NULL
);

CREATE TABLE IF NOT EXISTS agent_keys (
    agent_id VARCHAR(64) PRIMARY KEY,
    token_hash VARCHAR(128) NOT NULL,
    description VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    revoked INTEGER DEFAULT 0
);
