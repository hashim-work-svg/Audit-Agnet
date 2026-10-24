-- Deterministic Synthetic Seed Data for MCP-Guard Demo and Tests
-- All names, emails, addresses, and phone numbers are completely synthetic.

-- Customers with sensitive PII for masking verification
INSERT INTO customers (id, full_name, email, phone, address, credit_card_last4, ssn_last4, created_at) VALUES
(1, 'Alice Vance', 'alice.vance@example.corp', '+1-555-0101', '101 Cyber Way, Silicon Valley, CA 94025', '4321', '6789', '2026-01-15 10:30:00'),
(2, 'Bob Mercer', 'bob.mercer@testmail.org', '+1-555-0102', '202 Harbor Blvd, Boston, MA 02110', '8765', '1234', '2026-02-10 14:15:00'),
(3, 'Carol Danvers', 'carol.danvers@demo.net', '+1-555-0103', '303 Summit Ave, Seattle, WA 98101', '9012', '4567', '2026-03-01 09:00:00'),
(4, 'David Zhao', 'david.zhao@synthetic.io', '+1-555-0104', '404 Pine St, Austin, TX 78701', '3456', '7890', '2026-03-12 11:45:00'),
(5, 'Elena Rostova', 'elena.rostova@mockidentity.dev', '+1-555-0105', '505 Oak Lane, Denver, CO 80202', '7890', '2345', '2026-04-05 16:20:00');

-- Products
INSERT INTO products (id, sku, name, category, price_cents, stock_quantity, created_at) VALUES
(1, 'SKU-SEC-001', 'Hardware Security Key FIDO2', 'Security', 4500, 150, '2026-01-01 00:00:00'),
(2, 'SKU-SEC-002', 'Encrypted NVMe SSD 1TB', 'Hardware', 12900, 75, '2026-01-02 00:00:00'),
(3, 'SKU-NET-003', 'Managed Gigabit Switch 24-Port', 'Networking', 24900, 30, '2026-01-05 00:00:00'),
(4, 'SKU-SFT-004', 'Static Analysis Suite License', 'Software', 49900, 500, '2026-01-10 00:00:00'),
(5, 'SKU-ACC-005', 'Shielded Cat6A Patch Cable 10ft', 'Accessories', 1200, 600, '2026-01-12 00:00:00');

-- Orders
INSERT INTO orders (id, customer_id, order_status, total_cents, shipping_address, created_at) VALUES
(101, 1, 'DELIVERED', 17400, '101 Cyber Way, Silicon Valley, CA 94025', '2026-04-10 11:00:00'),
(102, 2, 'PROCESSING', 4500, '202 Harbor Blvd, Boston, MA 02110', '2026-04-12 15:30:00'),
(103, 3, 'SHIPPED', 74800, '303 Summit Ave, Seattle, WA 98101', '2026-04-15 08:45:00'),
(104, 4, 'CANCELLED', 12900, '404 Pine St, Austin, TX 78701', '2026-04-18 13:20:00'),
(105, 5, 'DELIVERED', 26100, '505 Oak Lane, Denver, CO 80202', '2026-04-20 17:10:00');

-- Order Items
INSERT INTO order_items (id, order_id, product_id, quantity, unit_price_cents) VALUES
(1, 101, 1, 1, 4500),
(2, 101, 2, 1, 12900),
(3, 102, 1, 1, 4500),
(4, 103, 3, 2, 24900),
(5, 103, 4, 1, 25000),
(6, 104, 2, 1, 12900),
(7, 105, 3, 1, 24900),
(8, 105, 5, 1, 1200);

-- Demo Agent Keys (Token hashes: SHA-256 of synthetic demo tokens)
-- "agent-token-analytics-12345" -> e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 (example)
-- Actual hash of "demo-token-analytics": sha256("demo-token-analytics") = 8d39e31d4b684cbfe36fe05c74f51e0640df11cc714d2a138c227dbd76378e9b
INSERT INTO agent_keys (agent_id, token_hash, description, created_at, revoked) VALUES
('analytics-agent', '8d39e31d4b684cbfe36fe05c74f51e0640df11cc714d2a138c227dbd76378e9b', 'Read-only business analytics agent with PII masking', '2026-01-01 00:00:00', 0),
('support-agent', 'd5b4a53075b6e082159846b08051759d57a957a66164ea5a39cb68bcf82e817a', 'Customer support tier 1 agent with customer email unmasked', '2026-01-01 00:00:00', 0),
('revoked-agent', '9f83c605188822f83d85045e75d2537f4048b8ff2e5aacf60f9d2a65e373b06c', 'Decommissioned test agent', '2026-01-01 00:00:00', 1);
