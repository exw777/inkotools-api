CREATE TABLE IF NOT EXISTS gdb_users (
    username text NOT NULL UNIQUE,
    password text NOT NULL,
    token text NOT NULL UNIQUE);
