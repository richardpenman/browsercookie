# -*- coding: utf-8 -*-
__doc__ = 'Load browser cookies into a cookiejar'

import contextlib
import os
import sys
import time
import glob
import base64
from pathlib import Path

if sys.platform == 'win32':
    from win32 import win32crypt #pywin32

try:
    import cookielib
except ImportError:
    import http.cookiejar as cookielib
from contextlib import contextmanager
import tempfile
try:
    import json
except ImportError:
    import simplejson as json
try:
    import ConfigParser as configparser
except ImportError:
    import configparser
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

try:
    # should use pysqlite2 to read the cookies.sqlite on Windows
    # otherwise will raise the "sqlite3.DatabaseError: file is encrypted or is not a database" exception
    from pysqlite2 import dbapi2 as sqlite3
except ImportError:
    import sqlite3

if sys.platform == 'darwin': # darwin is OSX
    from struct import unpack
    try:
        from StringIO import StringIO # only works for python2
    except ImportError:
        from io import BytesIO as StringIO # only works for python3

import lz4.block
import keyring


class BrowserCookieError(Exception):
    pass


@contextmanager
def create_local_copy(cookie_path, suffix='.sqlite'):
    """
    Make a local copy of the sqlite cookie database and return the new filename.
    This is necessary in case this database is still being written to while the user browses
    to avoid sqlite locking errors.
    """
    # check if cookie file exists
    if os.path.exists(cookie_path):
        # copy to random name in tmp folder
        tmp_cookie_file = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)
        tmp_cookie_path = tmp_cookie_file.name
        try:
            with contextlib.closing(tmp_cookie_file):
                with open(cookie_path, 'rb') as cookie_file:
                    tmp_cookie_file.write(cookie_file.read())
            yield tmp_cookie_path
        finally:
            os.remove(tmp_cookie_path)
    else:
        raise BrowserCookieError('Can not find cookie file at: ' + cookie_path)


class BrowserCookieLoader(object):
    def __init__(self, cookie_files=None):
        cookie_files = cookie_files or self.find_cookie_files()
        self.cookie_files = list(cookie_files)

    def find_cookie_files(self):
        '''Return a list of cookie file locations valid for this loader'''
        raise NotImplementedError

    def get_cookies(self):
        '''Return all cookies (May include duplicates from different sources)'''
        raise NotImplementedError

    def load(self):
        '''Load cookies into a cookiejar'''
        cookie_jar = cookielib.CookieJar()
        for cookie in sorted(self.get_cookies(), key=lambda cookie: cookie.expires):
            cookie_jar.set_cookie(cookie)
        return cookie_jar


class ChromeBased(BrowserCookieLoader):
    def get_cookies(self):
        salt = b'saltysalt'
        length = 16
        keys = []
        if sys.platform == 'darwin':
            # running Chrome on OSX
            my_pass = keyring.get_password('Chrome Safe Storage', 'Chrome')
            my_pass = my_pass.encode('utf8')
            iterations = 1003
            passwords = [my_pass]

        elif sys.platform.startswith('linux'):
            import secretstorage

            # running Chrome on Linux
            passwords = [b'peanuts']  # v10 key

            with contextlib.closing(secretstorage.dbus_init()) as bus:
                collection = secretstorage.get_default_collection(bus)
                schema = "chrome_libsecret_os_crypt_password_v2"
                for item in collection.search_items({"xdg:schema": schema}):
                    passwords.append(item.get_secret())

            iterations = 1

        elif sys.platform == 'win32':
            # per-file encryption key location
            passwords = []
            iterations = 0
        else:
            raise BrowserCookieError('Unsupported operating system: ' + sys.platform)

        if passwords and iterations:
            sha1 = hashes.SHA1()
            for my_pass in passwords:
                kdf = PBKDF2HMAC(
                    algorithm=sha1,
                    length=length,
                    salt=salt,
                    iterations=iterations,
                )
                keys.append(kdf.derive(my_pass))

        key_local_state_path = None
        for cookie_file in self.cookie_files:
            if sys.platform == 'win32':
                cookie_path = Path(cookie_file).absolute()
                user_dir_path = next((p for p in cookie_path.parents if p.name == 'User Data'), None)
                local_state_path = user_dir_path / 'Local State' if user_dir_path is not None else None
                if local_state_path is None or not local_state_path.exists():
                    raise BrowserCookieError('Failed to find Local State folder for cookie file ' + str(cookie_path))
                if key_local_state_path != local_state_path:
                    with open(local_state_path, 'rb') as file:
                        encrypted_key = json.loads(file.read())['os_crypt']['encrypted_key']
                    encrypted_key = base64.b64decode(encrypted_key)  # Base64 decoding
                    encrypted_key = encrypted_key[5:]  # Remove DPAPI

                    key_local_state_path = local_state_path
                    keys = [win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]]  # Decrypt key

            with create_local_copy(cookie_file) as tmp_cookie_file:
                with contextlib.closing(sqlite3.connect(tmp_cookie_file)) as con:
                    con.text_factory = bytes
                    cur = con.cursor()
                    cur.execute('SELECT value FROM meta WHERE key = "version";')
                    version = int(cur.fetchone()[0])
                    query = 'SELECT host_key, path, is_secure, expires_utc, name, value, encrypted_value FROM cookies;'
                    if version < 10:
                        query = query.replace('is_', '')
                    cur.execute(query)
                    for item in cur.fetchall():
                        host, path, secure, expires, name = item[:5]
                        host = host.decode("utf-8")
                        path = path.decode("utf-8")
                        name = name.decode("utf-8")
                        expires = expires / 1e6 - 11644473600  # 1601/1/1
                        for key in keys:
                            try:
                                value = self._decrypt(item[5], item[6], name, path, key, version)
                            except (UnicodeDecodeError, ValueError):
                                pass
                            else:
                                yield create_cookie(host, path, secure, expires, name, value)
                                break
                        else:
                            raise BrowserCookieError("Error decrypting cookie " + name + " for " + host)


    def _decrypt(self, value, encrypted_value, cookiename, sitename, key, version):

        """Decrypt encoded cookies
        """
        if (sys.platform == 'darwin') or sys.platform.startswith('linux'):
            if value or (encrypted_value[:3] != b'v10' and encrypted_value[:3] != b'v11'):
                return value

            # Encrypted cookies should be prefixed with 'v10' or 'v11' according to the
            # Chromium code. Strip it off.
            encrypted_value = encrypted_value[3:]

            aes = algorithms.AES(key)
            iv = b' ' * (aes.block_size // 8)
            cipher = Cipher(aes, modes.CBC(iv))
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(encrypted_value) + decryptor.finalize()

            unpadder = padding.PKCS7(aes.block_size).unpadder()
            plaintext = unpadder.update(plaintext) + unpadder.finalize()
        else:
            # Must be win32 (on win32, all chrome cookies are encrypted)

            plaintext = ""
            if encrypted_value[:3] == b'v10':
                try:
                    data = encrypted_value # the encrypted cookie
                    nonce = data[3:3 + 12]
                    ciphertext = data[3 + 12:-16]
                    tag = data[-16:]
                    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
                    decryptor = cipher.decryptor()
                    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
                except:
                    raise BrowserCookieError("Error decrypting V80+ cookie: " + str(cookiename) + " from site " + str(sitename))
            else:
                try:
                    plaintext = win32crypt.CryptUnprotectData(encrypted_value, None, None, None, 0)[1]
                except:
                    raise BrowserCookieError("Error decrypting cookie: " + str(cookiename) + " from site " + str(sitename))

        if version >= 24:
            plaintext = plaintext[32:]

        return plaintext.decode("utf-8")


class Chrome(ChromeBased):
    def __str__(self):
        return 'chrome'

    def find_cookie_files(self):
        for pattern in [
            os.path.expanduser('~/Library/Application Support/Google/Chrome/Default/Cookies'),
            os.path.expanduser('~/Library/Application Support/Google/Chrome/Profile */Cookies'),
            os.path.expanduser('~/.config/google-chrome/Default/Cookies'),
            os.path.expanduser('~/.config/google-chrome/Profile */Cookies'),
            os.path.join(os.getenv('LOCALAPPDATA', ''), r'Google\Chrome\User Data\Default\Cookies'),
            os.path.join(os.getenv('LOCALAPPDATA', ''), r'Google\Chrome\User Data\Default\Network\Cookies'),
            os.path.join(os.getenv('LOCALAPPDATA', ''), r'Google\Chrome\User Data\Profile *\Cookies'),
        ]:
            for result in glob.glob(pattern):
                yield result

class Brave(ChromeBased):
    def __str__(self):
        return 'brave'

    def find_cookie_files(self):
        for pattern in [
            os.path.expanduser('~/Library/Application Support/BraveSoftware/Brave-Browser/Default/Cookies'),
            os.path.expanduser('~/Library/Application Support/BraveSoftware/Brave-Browser/Profile */Cookies'),
            os.path.expanduser('~/.config/BraveSoftware/Brave-Browser/Default/Cookies'),
            os.path.expanduser('~/.config/BraveSoftware/Brave-Browser/Profile */Cookies'),
            os.path.join(os.getenv('LOCALAPPDATA', ''), r'BraveSoftware\Brave-Browser\User Data\Default\Cookies'),
            os.path.join(os.getenv('LOCALAPPDATA', ''), r'BraveSoftware\Brave-Browser\User Data\Default\Network\Cookies'),
            os.path.join(os.getenv('LOCALAPPDATA', ''), r'BraveSoftware\Brave-Browser\User Data\Profile *\Cookies'),
        ]:
            for result in glob.glob(pattern):
                yield result


class Chromium(ChromeBased):
    def __str__(self):
        return 'chromium'

    def find_cookie_files(self):
        for pattern in [
            os.path.expanduser('~/Library/Application Support/Google/Chromium/Default/Cookies'),
            os.path.expanduser('~/Library/Application Support/Google/Chromium/Profile */Cookies'),
            os.path.expanduser('~/.config/chromium/Default/Cookies'),
            os.path.expanduser('~/.config/chromium/Profile */Cookies'),
            os.path.join(os.getenv('LOCALAPPDATA', ''), r'Google\Chromium\User Data\Default\Cookies'),
            os.path.join(os.getenv('LOCALAPPDATA', ''), r'Google\Chromium\User Data\Default\Network\Cookies'),
            os.path.join(os.getenv('LOCALAPPDATA', ''), r'Google\Chromium\User Data\Profile *\Cookies'),
        ]:
            for result in glob.glob(pattern):
                yield result


class Vivaldi(ChromeBased):
    def __str__(self):
        return 'vivaldi'

    def find_cookie_files(self):
        for pattern in [
            os.path.expanduser('~/Library/Application Support/Vivaldi/Default/Cookies'),
            os.path.expanduser('~/Library/Application Support/Vivaldi/Profile */Cookies'),
            os.path.expanduser('~/.config/vivaldi/Default/Cookies'),
            os.path.expanduser('~/.config/vivaldi/Profile */Cookies'),
            os.path.join(os.getenv('LOCALAPPDATA', ''), r'Vivaldi\User Data\Default\Cookies'),
            os.path.join(os.getenv('LOCALAPPDATA', ''), r'Vivaldi\User Data\Default\Network\Cookies'),
            os.path.join(os.getenv('LOCALAPPDATA', ''), r'Vivaldi\User Data\Profile *\Cookies'),
        ]:
            for result in glob.glob(pattern):
                yield result

class Edge(ChromeBased):
    def __str__(self):
        return 'edge'

    def find_cookie_files(self):
        for pattern in [
            os.path.expanduser('~/Library/Application Support/Microsoft/Edge/Default/Cookies'),
            os.path.expanduser('~/Library/Application Support/Microsoft/Edge/Profile */Cookies'),
            os.path.expanduser('~/.config/microsoft-edge/Default/Cookies'),
            os.path.expanduser('~/.config/microsoft-edge/Profile */Cookies'),
            os.path.join(os.getenv('LOCALAPPDATA', ''), r'Microsoft\Edge\User Data\Default\Cookies'),
            os.path.join(os.getenv('LOCALAPPDATA', ''), r'Microsoft\Edge\User Data\Default\Network\Cookies'),
            os.path.join(os.getenv('LOCALAPPDATA', ''), r'Microsoft\Edge\User Data\Profile *\Cookies'),
        ]:
            for result in glob.glob(pattern):
                yield result


class EdgeDev(ChromeBased):
    def __str__(self):
        return 'edge-dev'

    def find_cookie_files(self):
        for pattern in [
            os.path.expanduser('~/Library/Application Support/Microsoft/Edge Dev/Default/Cookies'),
            os.path.expanduser('~/Library/Application Support/Microsoft/Edge Dev/Profile */Cookies'),
            os.path.expanduser('~/.config/microsoft-edge-dev/Default/Cookies'),
            os.path.expanduser('~/.config/microsoft-edge-dev/Profile */Cookies'),
            os.path.join(os.getenv('LOCALAPPDATA', ''), r'Microsoft\Edge Dev\User Data\Default\Cookies'),
            os.path.join(os.getenv('LOCALAPPDATA', ''), r'Microsoft\Edge Dev\User Data\Default\Network\Cookies'),
            os.path.join(os.getenv('LOCALAPPDATA', ''), r'Microsoft\Edge Dev\User Data\Profile *\Cookies'),
        ]:
            for result in glob.glob(pattern):
                yield result


class Firefox(BrowserCookieLoader):
    def __str__(self):
        return 'firefox'

    def parse_profile(self, profile):
        profile_dir = Path(os.path.dirname(profile))

        cp = configparser.ConfigParser()
        cp.read(profile, encoding='utf-8')

        path = None
        for section in cp.sections():
            if section.startswith('Install'):
                if cp.has_option(section, 'Default'):
                    path = profile_dir / cp.get(section, 'Default')
                    break
            else:
                try:
                    if cp.getboolean(section, 'IsRelative'):
                        profile_path = profile_dir / cp.get(section, 'Path')
                    else:
                        profile_path = Path(cp.get(section, 'Path'))

                    if not path:
                        path = profile_path
                    elif cp.getboolean(section, 'Default'):
                        path = profile_path
                except configparser.NoOptionError:
                    pass
        if path:
            return str(path.expanduser().absolute())
        raise BrowserCookieError('No default Firefox profile found')

    def find_default_profile(self):
        if sys.platform == 'darwin':
            return glob.glob(os.path.expanduser('~/Library/Application Support/Firefox/profiles.ini'))
        elif sys.platform.startswith('linux'):
            trad_filename = glob.glob(os.path.expanduser('~/.mozilla/firefox/profiles.ini'))
            snap_filename = glob.glob(os.path.expanduser('~/snap/firefox/common/.mozilla/firefox/profiles.ini'))
            return trad_filename + snap_filename
        elif sys.platform == 'win32':
            return glob.glob(os.path.join(os.getenv('APPDATA', ''), 'Mozilla/Firefox/profiles.ini'))
        else:
            raise BrowserCookieError('Unsupported operating system: ' + sys.platform)

    def find_cookie_files(self):
        profile = self.find_default_profile()
        if not profile:
            raise BrowserCookieError('Could not find default Firefox profile')
        path = self.parse_profile(profile[0])
        if not path:
            raise BrowserCookieError('Could not find path to default Firefox profile')

        cookie_file = os.path.expanduser(path + '/cookies.sqlite')
        if os.path.exists(cookie_file):
            for session_file in [
                os.path.join(os.path.dirname(cookie_file), 'sessionstore-backups', 'recovery.js'),
                os.path.join(os.path.dirname(cookie_file), 'sessionstore-backups', 'recovery.json'),
                os.path.join(os.path.dirname(cookie_file), 'sessionstore-backups', 'recovery.jsonlz4'),
                os.path.join(os.path.dirname(cookie_file), 'sessionstore.js'),
                os.path.join(os.path.dirname(cookie_file), 'sessionstore.json'),
                os.path.join(os.path.dirname(cookie_file), 'sessionstore.jsonlz4'),
            ]:
                if os.path.exists(session_file):
                    yield session_file
            yield cookie_file
        else:
            raise BrowserCookieError('Failed to find Firefox cookies')

    def get_cookies(self):
        has_session_files = False
        for cookie_file in self.cookie_files:
            cookie_path = Path(cookie_file)
            with create_local_copy(cookie_file, suffix=cookie_path.suffix) as tmp_cookie_file:
                if cookie_path.suffix == '.sqlite':
                    with contextlib.closing(sqlite3.connect(tmp_cookie_file)) as con:
                        cur = con.cursor()
                        cur.execute('select host, path, isSecure, expiry, name, value from moz_cookies')

                        for item in cur.fetchall():
                            yield create_cookie(*item)
                else:
                    json_data = None
                    with open(tmp_cookie_file, 'rb') as session_file:
                        if tmp_cookie_file.endswith('4'):
                            try:
                                # skip the first 8 bytes to avoid decompress failure (custom Mozilla header)
                                session_file.seek(8)
                                json_data = json.loads(lz4.block.decompress(session_file.read()).decode())
                            except IOError as e:
                                print('Could not read file:', str(e))
                            except ValueError as e:
                                print('Error parsing Firefox session file:', str(e))
                        else:
                            try:
                                json_data = json.loads(session_file.read().decode('utf-8'))
                            except IOError as e:
                                print('Could not read file:', str(e))
                            except ValueError as e:
                                print('Error parsing firefox session JSON:', str(e))

                    if json_data is not None:
                        has_session_files = True
                        expires = str(int(time.time()) + 3600 * 24 * 7)
                        for window in json_data.get('windows', []) + [json_data]:
                            for cookie in window.get('cookies', []):
                                yield create_cookie(cookie.get('host', ''), cookie.get('path', ''), False, expires, cookie.get('name', ''), cookie.get('value', ''))
        if not has_session_files:
            print('Could not find any Firefox session files')


class Safari(BrowserCookieLoader):
    def __str__(self):
        return 'safari'

    def find_cookie_files(self):
        if (sys.platform != 'darwin'):  # checks if using OSX
            BrowserCookieError('Safari is only available on OSX')
        else:
            cookie_files = glob.glob(os.path.expanduser('~/Library/Cookies')) # no actual use of cookie files because we only have need one specific cookie file
            if cookie_files:
                return cookie_files
            else:
                raise BrowserCookieError('Failed to find Safari cookies')

    def get_cookies(self):
        FilePath = os.path.expanduser('~/Library/Cookies/Cookies.binarycookies')

        try:
            binary_file = open(FilePath, 'rb')
        except IOError:
            BrowserCookieError('File Not Found :' + FilePath)
            exit()

        binary_file.read(4)# will equal 'cook', which stands for cookies

        num_pages = unpack('>i', binary_file.read(4))[0]

        page_sizes = []
        for _ in range(num_pages):
            page_sizes.append(unpack('>i', binary_file.read(4))[0])

        pages = []
        for ps in page_sizes:
            pages.append(binary_file.read(ps))

        for page in pages:
            page = StringIO(page)
            page.read(4)
            num_cookies = unpack('<i', page.read(4))[0]

            cookie_offsets = []
            for _ in range(num_cookies):
                cookie_offsets.append(unpack('<i', page.read(4))[0])

            page.read(4)

            cookie = ''
            for offset in cookie_offsets:
                page.seek(offset)
                cookiesize = unpack('<i', page.read(4))[0]
                cookie = StringIO(page.read(cookiesize))

                cookie.read(4)

                flags = unpack('<i', cookie.read(4))[0]
                cookie_flags = ''
                if flags == 0:
                    cookie_flags = False # if nothing at all
                if flags == 1:
                    cookie_flags = True # if Secure
                elif flags == 4:
                    cookie_flags = False # if Http only
                elif flags == 5:
                    cookie_flags = True # if Secure and Http only
                else:
                    cookie_flags = False # if Unknown

                cookie.read(4)

                urloffset = unpack('<i', cookie.read(4))[0]
                nameoffset = unpack('<i', cookie.read(4))[0]
                pathoffset = unpack('<i', cookie.read(4))[0]
                valueoffset = unpack('<i', cookie.read(4))[0]

                expiry_date = str(int(unpack('<d', cookie.read(8))[0] + 978307200)) # 978307200 because mac's time starts at: 2001, 1, 1

                # create_date = str(int(unpack('<d', cookie.read(8))[0] + 978307200)) no need of it here...

                # endofcookie = cookie.read(8) no need it either...

                cookie.seek(urloffset - 4)
                host = ''
                u = cookie.read(1)
                while unpack('<b', u)[0] != 0:
                    host = host + u.decode("utf-8") # in bytes have to be decoded
                    u = cookie.read(1)

                cookie.seek(nameoffset - 4)
                name = ''
                n = cookie.read(1)
                while unpack('<b', n)[0] != 0:
                    name = name + n.decode("utf-8")
                    n = cookie.read(1)

                cookie.seek(pathoffset - 4)
                path = ''
                pa = cookie.read(1)
                while unpack('<b', pa)[0] != 0:
                    path = path + pa.decode("utf-8")
                    pa = cookie.read(1)

                cookie.seek(valueoffset - 4)
                value = ''
                va = cookie.read(1)
                while unpack('<b', va)[0] != 0:
                    value = value + va.decode("utf-8")
                    va = cookie.read(1)

                yield create_cookie(host, path, cookie_flags, expiry_date, name, value)

        binary_file.close()



def create_cookie(host, path, secure, expires, name, value):
    """Shortcut function to create a cookie
    """
    return cookielib.Cookie(0, name, value, None, False, host, host.startswith('.'), host.startswith('.'), path, True, secure, expires, False, None, None, {})

def brave(cookie_files=None):
    """Returns a cookiejar of the cookies used by Brave
    """
    return Brave(cookie_files).load()

def chrome(cookie_files=None):
    """Returns a cookiejar of the cookies used by Chrome
    """
    return Chrome(cookie_files).load()


def chromium(cookie_files=None):
    """Returns a cookiejar of the cookies used by Chromium
    """
    return Chromium(cookie_files).load()


def vivaldi(cookie_files=None):
    """Returns a cookiejar of the cookies used by Vivaldi
    """
    return Vivaldi(cookie_files).load()


def edge(cookie_files=None):
    """Returns a cookiejar of the cookies used by Microsoft Edge
    """
    return Edge(cookie_files).load()


def edge_dev(cookie_files=None):
    """Returns a cookiejar of the cookies used by Microsoft Edge Dev
    """
    return EdgeDev(cookie_files).load()


def firefox(cookie_files=None):
    """Returns a cookiejar of the cookies and sessions used by Firefox
    """
    return Firefox(cookie_files).load()


def safari(cookie_files=None):
    """Returns a cookiejar of the cookies used by safari
    """
    return Safari(cookie_files).load()


def _get_cookies():
    '''Return all cookies from all browsers'''
    for klass in [Brave, Chrome, Chromium, Vivaldi, Edge, EdgeDev, Firefox]:
        try:
            for cookie in klass().get_cookies():
                yield cookie
        except BrowserCookieError:
            pass


def load():
    """Try to load cookies from all supported browsers and return combined cookiejar
    """
    cookie_jar = cookielib.CookieJar()

    for cookie in sorted(_get_cookies(), key=lambda cookie: cookie.expires):
        cookie_jar.set_cookie(cookie)

    return cookie_jar
