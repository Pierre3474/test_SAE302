-- ============================================================
-- SAE302 — Schema de la base de donnees PKI
-- ============================================================

DROP TABLE IF EXISTS crls CASCADE;
DROP TABLE IF EXISTS certificates CASCADE;
DROP TABLE IF EXISTS csrs CASCADE;
DROP TABLE IF EXISTS keys CASCADE;
DROP TABLE IF EXISTS user_pkis CASCADE;
DROP TABLE IF EXISTS pkis CASCADE;
DROP TABLE IF EXISTS logs CASCADE;
DROP TABLE IF EXISTS users CASCADE;

-- 1. Utilisateurs
CREATE TABLE users (
    id              SERIAL PRIMARY KEY,
    username        VARCHAR(50) UNIQUE NOT NULL,
    password_hash   TEXT NOT NULL,
    role            VARCHAR(20) DEFAULT 'viewer'
                    CHECK (role IN ('admin', 'editor', 'viewer')),
    enabled         BOOLEAN DEFAULT TRUE,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_login      TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_users_username ON users(username);

-- 2. PKI (autorites de certification)
CREATE TABLE pkis (
    id          SERIAL PRIMARY KEY,
    name        VARCHAR(100) UNIQUE NOT NULL,
    subject     TEXT NOT NULL,
    created_by  INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_pkis_name ON pkis(name);

-- 3. Association utilisateur <-> PKI (many-to-many)
CREATE TABLE user_pkis (
    user_id     INTEGER REFERENCES users(id) ON DELETE CASCADE,
    pki_id      INTEGER REFERENCES pkis(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, pki_id)
);

-- 4. Cles cryptographiques
CREATE TABLE keys (
    id              SERIAL PRIMARY KEY,
    pki_id          INTEGER NOT NULL REFERENCES pkis(id) ON DELETE CASCADE,
    key_name        VARCHAR(100) NOT NULL,
    algorithm       VARCHAR(10) DEFAULT 'RSA' CHECK (algorithm IN ('RSA', 'EC')),
    key_size        VARCHAR(20) DEFAULT '2048',
    private_key_pem TEXT NOT NULL,
    public_key_pem  TEXT NOT NULL,
    encrypted       BOOLEAN DEFAULT FALSE,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (pki_id, key_name)
);

-- 5. Demandes de certificat (CSR)
CREATE TABLE csrs (
    id          SERIAL PRIMARY KEY,
    pki_id      INTEGER NOT NULL REFERENCES pkis(id) ON DELETE CASCADE,
    key_name    VARCHAR(100) NOT NULL,
    subject     TEXT NOT NULL,
    extensions  TEXT,
    csr_pem     TEXT NOT NULL,
    created_at  TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 6. Certificats
CREATE TABLE certificates (
    id              SERIAL PRIMARY KEY,
    pki_id          INTEGER NOT NULL REFERENCES pkis(id) ON DELETE CASCADE,
    key_name        VARCHAR(100) NOT NULL,
    subject         TEXT NOT NULL,
    issuer_cert_id  INTEGER REFERENCES certificates(id) ON DELETE SET NULL,
    cert_pem        TEXT NOT NULL,
    serial_number   VARCHAR(64) UNIQUE NOT NULL,
    not_before      TIMESTAMP WITH TIME ZONE NOT NULL,
    not_after       TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked         BOOLEAN DEFAULT FALSE,
    revoked_at      TIMESTAMP WITH TIME ZONE,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_certificates_serial ON certificates(serial_number);
CREATE INDEX idx_certificates_pki ON certificates(pki_id);

-- 7. Listes de revocation (CRL)
CREATE TABLE crls (
    id          SERIAL PRIMARY KEY,
    pki_id      INTEGER NOT NULL REFERENCES pkis(id) ON DELETE CASCADE,
    crl_pem     TEXT NOT NULL,
    next_update TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at  TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 8. Logs d'audit
CREATE TABLE logs (
    id          SERIAL PRIMARY KEY,
    timestamp   TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    user_id     INTEGER REFERENCES users(id) ON DELETE SET NULL,
    ip_address  INET,
    action      VARCHAR(50) NOT NULL,
    details     TEXT
);

CREATE INDEX idx_logs_timestamp ON logs(timestamp);
CREATE INDEX idx_logs_user ON logs(user_id);
