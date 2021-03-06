DROP TABLE IF EXISTS stats;
DROP TABLE IF EXISTS vms;
DROP TABLE IF EXISTS tags;
DROP TABLE IF EXISTS fw_rules;
DROP TABLE IF EXISTS tag_vms;
DROP TABLE IF EXISTS attack_surfaces;
CREATE TABLE stats (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  duration REAL NOT NULL
);

CREATE TABLE vms (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  vm_id TEXT NOT NULL,
  name TEXT NOT NULL
);

CREATE TABLE tags (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL
);

CREATE TABLE tag_vms (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tag TEXT NOT NULL,
  vm TEXT NOT NULL,
  FOREIGN KEY (tag) REFERENCES tags (id),
  FOREIGN KEY (vm) REFERENCES vms (id)
);

CREATE TABLE fw_rules (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  src TEXT NOT NULL,
  dst TEXT NOT NULL,
  FOREIGN KEY (src) REFERENCES tags (id),
  FOREIGN KEY (dst) REFERENCES tags (id)
);

CREATE TABLE attack_surfaces (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  vm TEXT NOT NULL,
  attacker TEXT NOT NULL,
  FOREIGN KEY (vm) REFERENCES vms (id),
  FOREIGN KEY (attacker) REFERENCES vms (id)
);