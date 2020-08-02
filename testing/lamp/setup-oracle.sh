#!/bin/bash
/opt/oracle/instantclient/sqlplus system/oracle@//oracle/xe <<'EOF'
CREATE USER anime_db IDENTIFIED BY Password1;
GRANT CONNECT, RESOURCE, DBA TO anime_db;

CREATE TABLE anime_db.anime (
    id NUMBER,
    name VARCHAR2(50)
);

DELETE FROM anime_db.anime;

INSERT INTO anime_db.anime(id, name) VALUES(1, 'Cowboy Bebop');
INSERT INTO anime_db.anime(id, name) VALUES(2, 'Great Teacher Onizuka');
INSERT INTO anime_db.anime(id, name) VALUES(3, 'One Piece');
INSERT INTO anime_db.anime(id, name) VALUES(4, 'Hajime No Ippo');
EOF
