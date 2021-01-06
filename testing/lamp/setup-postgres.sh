#!/bin/bash
PGPASSWORD=Password1 psql -h postgres -U anime_user -d anime_db <<'EOF'
DROP TABLE IF EXISTS anime;
CREATE TABLE anime (
  id SERIAL PRIMARY KEY,
  name TEXT
);
INSERT INTO anime (name) VALUES ('Cowboy Bebop');
INSERT INTO anime (name) VALUES ('Great Teacher Onizuka');
INSERT INTO anime (name) VALUES ('One Piece');
INSERT INTO anime (name) VALUES ('Hajime No Ippo');
EOF
