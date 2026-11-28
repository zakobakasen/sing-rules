PRAGMA foreign_keys=ON;
CREATE TABLE settings (
 id INTEGER PRIMARY KEY CHECK(id=1),
 listen TEXT NOT NULL, password TEXT,
 public_url TEXT NOT NULL DEFAULT '', issuer TEXT NOT NULL DEFAULT '',
 client_id TEXT NOT NULL DEFAULT '', audience TEXT NOT NULL DEFAULT '', scope TEXT NOT NULL DEFAULT '',
 imports TEXT NOT NULL DEFAULT '[]', auth_epoch INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE roles (
 issuer TEXT NOT NULL, sub TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','user')),
 PRIMARY KEY(issuer,sub)
);
CREATE TABLE sessions (digest BLOB PRIMARY KEY, expires INTEGER NOT NULL);
CREATE TABLE configs (
 id INTEGER PRIMARY KEY, owner TEXT NOT NULL, note TEXT NOT NULL CHECK(note<>''),
 sr TEXT, base TEXT, output TEXT, revision INTEGER NOT NULL DEFAULT 0,
 UNIQUE(owner,note), UNIQUE(owner,id)
);
CREATE TABLE links (
 id INTEGER PRIMARY KEY, owner TEXT NOT NULL, note TEXT NOT NULL CHECK(note<>''), token TEXT NOT NULL UNIQUE,
 target INTEGER, UNIQUE(owner,note), FOREIGN KEY(owner,target) REFERENCES configs(owner,id)
);
CREATE TABLE blobs (tag TEXT PRIMARY KEY, bytes BLOB NOT NULL);
