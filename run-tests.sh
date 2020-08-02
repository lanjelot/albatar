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
  docker-compose logs oracle | grep -c 'Starting Oracle Database' | grep -q 2 \
   && docker-compose exec lamp bash /var/www/html/demo/setup-oracle.sh | grep -c 'row created' | grep -q 4 && break
done

run()
{
  echo
  sed -i -e 's,^sqli =,#sqli =,' -e "/^#sqli = $1/ s,^#,," demo.py
  echo "$ $@"
  docker-compose run --no-deps --rm --entrypoint 'timeout 15s python3 demo.py' albatar "$@"
  echo
}

run 'MySQL_Inband(mysql_union())' -b --current-user --current-db --users --passwords --dbs
run 'MySQL_Inband(mysql_error())' -b
run 'MySQL_Blind(mysql_boolean_regexp())' -b
run 'MySQL_Blind(mysql_boolean_binary())' -b
run 'MySQL_Blind(mysql_time())' -b

run 'MySQL_Inband(mysql_union())' --dump -D anime_db --tables
run 'MySQL_Inband(mysql_union())' --dump -D anime_db -T anime --columns
run 'MySQL_Inband(mysql_union())' --dump -D anime_db -T anime -C id,name

run 'MSSQL_Inband(mssql_union())' -b
run 'MSSQL_Inband(mssql_error())' -b
run 'MSSQL_Blind(mssql_boolean())' -b
run 'MSSQL_Blind(mssql_time())' -b

run 'Oracle_Inband(oracle_union())' -b
#run 'Oracle_Inband(oracle_error())' -b # broken
run 'Oracle_Blind(oracle_boolean())' -b
