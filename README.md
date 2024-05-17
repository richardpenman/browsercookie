Browser Cookie
==============

The **browsercookie** module loads cookies used by your web browser
into a cookiejar object. This can be useful if you want to use python to
download the same content you see in the web browser without needing to
login.

Install
-------

```python
pip install browsercookie
```

On Windows the builtin sqlite module will raise an error when loading
the FireFox database. An updated version of sqlite can be installed with:

```python
pip install pysqlite
```

Usage
-----

Here is a hack to extract the title from a webpage:

```python
>>> import re
>>> get_title = lambda html: re.findall('<title>(.*?)</title>', html, flags=re.DOTALL)[0].strip()
```

And here is the webpage title when downloaded normally:

```python
>>> import urllib2
>>> url = 'https://bitbucket.org/'
>>> public_html = urllib2.urlopen(url).read()
>>> get_title(public_html)
'Git and Mercurial code management for teams'
```

Now let's try with **browsercookie** - make sure you are logged into
Bitbucket in Firefox before trying this example:

```python
>>> import urllib.request
>>> public\_html = urllib.request.urlopen(url).read()
>>> opener = urllib.request.build\_opener(urllib.request.HTTPCookieProcessor(cj))
```

You should see your own username here, meaning the module successfully
loaded the cookies from Firefox.

Here is an alternative example with
[requests](http://docs.python-requests.org/en/latest/), this time
loading the Chrome cookies. Again make sure you are logged into
Bitbucket in Chrome before running this:

```python
>>> import requests
>>> cj = browsercookie.chrome()
>>> r = requests.get(url, cookies=cj)
>>> get_title(r.content)
'richardpenman / home &mdash; Bitbucket'
```

Alternatively if you don't know/care which browser has the cookies you
want then all available browser cookies can be loaded:

```python
>>> cj = browsercookie.load()
>>> r = requests.get(url, cookies=cj)
>>> get_title(r.content)
'richardpenman / home &mdash; Bitbucket'
```

Contribute
----------

So far the following platforms are supported:

-  **Chrome:** Linux, OSX, Windows
-  **Firefox:** Linux, OSX, Windows

However I only tested on a single version of each browser and so am not
sure if the cookie sqlite format changes location or format in
earlier/later versions. If you experience a problem please `open an
issue <https://bitbucket.org/richardpenman/browsercookie/issues/new>`__
which includes details of the browser version and operating system. Also
patches to support other browsers are very welcome, particularly for
Internet Explorer on Windows.

Acknowledgements
----------------

* Nathan Henrie for his example of [http://n8henrie.com/2013/11/use-chromes-cookies-for-easier-downloading-with-python-requests/](how to decode the Chrome cookies)
* Graeme Robinson for his Chrome Windows patch
