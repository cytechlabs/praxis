-- Create the groups table
CREATE TABLE IF NOT EXISTS groups (
    id INTEGER PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create index on name
CREATE INDEX IF NOT EXISTS ix_groups_name ON groups(name);

-- Insert default "All Systems" group
INSERT INTO groups (id, name, description) VALUES
(1, 'All Systems', 'Default group containing all systems');

-- Create the distros table
CREATE TABLE IF NOT EXISTS distros (
    id INTEGER PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    version VARCHAR(50) NOT NULL,
    release_date DATE NOT NULL,
    end_of_life_date DATE NOT NULL,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create index on name
CREATE INDEX IF NOT EXISTS ix_distros_name ON distros(name);

-- Insert supported Linux distributions into the distros table
-- Ubuntu LTS Versions
INSERT INTO distros (id, name, version, release_date, end_of_life_date) VALUES
(1, 'Ubuntu', '18.04', '2018-04-26', '2028-04-26');

INSERT INTO distros (id, name, version, release_date, end_of_life_date) VALUES
(2, 'Ubuntu', '20.04', '2020-04-23', '2030-04-23');

INSERT INTO distros (id, name, version, release_date, end_of_life_date) VALUES
(3, 'Ubuntu', '22.04', '2022-04-21', '2032-04-21');

-- RHEL Versions
INSERT INTO distros (id, name, version, release_date, end_of_life_date) VALUES
(4, 'RHEL', '8', '2019-05-07', '2029-05-31');

INSERT INTO distros (id, name, version, release_date, end_of_life_date) VALUES
(5, 'RHEL', '9', '2022-05-17', '2032-05-31');

-- Create the credentials table
CREATE TABLE IF NOT EXISTS credentials (
    id INTEGER PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    type VARCHAR(50) NOT NULL,
    username VARCHAR(255),
    password TEXT,
    ssh_key TEXT,
    vault_kv_path VARCHAR(255),
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create index on name
CREATE INDEX IF NOT EXISTS ix_credentials_name ON credentials(name);

-- Insert default admin credential
INSERT INTO credentials (id, name, type, username, password) VALUES
(1, 'default', 'name', 'admin', 'admin');
