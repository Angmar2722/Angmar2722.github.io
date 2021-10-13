import sys
from Crypto.Util.py3compat import byte_string
from Crypto.Util._file_system import pycryptodome_filename

#
# List of file suffixes for Python extensions
#
if sys.version_info[0] <= 3 or \
   (sys.version_info[0] == 3 and sys.version_info[1] <= 3):

    import imp
    extension_suffixes = []
    for ext, mod, typ in imp.get_suffixes():
        if typ == imp.C_EXTENSION:
            extension_suffixes.append(ext)

else:

    from importlib import machinery
    extension_suffixes = machinery.EXTENSION_SUFFIXES


try:
    from cffi import FFI

    ffi = FFI()
    null_pointer = ffi.NULL

    def load_lib(name, cdecl):
        """Load a shared library and return a handle to it.
        @name,  either an absolute path or the name of a library
                in the system search path.
        @cdecl, the C function declarations.
        """

        lib = ffi.dlopen(name)
        #ffi.cdef(cdecl)
        ffi.cdef(cdecl, override=True)
        return lib

    def c_ulong(x):
        """Convert a Python integer to unsigned long"""
        return x

    c_ulonglong = c_ulong

    def c_size_t(x):
        """Convert a Python integer to size_t"""
        return x

    def create_string_buffer(size):
        """Allocate the given amount of bytes (initially set to 0)"""
        return ffi.new("uint8_t[]", size)

    def get_c_string(c_string):
        """Convert a C string into a Python byte sequence"""
        return ffi.string(c_string)

    def get_raw_buffer(buf):
        """Convert a C buffer into a Python byte sequence"""
        return ffi.buffer(buf)[:]

    class VoidPointer(object):
        """Model a newly allocated pointer to void"""

        def __init__(self):
            self._pp = ffi.new("void *[1]")

        def get(self):
            return self._pp[0]

        def address_of(self):
            return self._pp

    Array = ffi.new("uint8_t[1]").__class__.__bases__

    backend = "cffi"

except ImportError:
    from ctypes import (CDLL, c_void_p, byref, c_ulong, c_ulonglong, c_size_t,
                        create_string_buffer)
    from ctypes.util import find_library
    from _ctypes import Array

    null_pointer = None

    def load_lib(name, cdecl):
        import platform
        bits, linkage = platform.architecture()
        if "." not in name and not linkage.startswith("Win"):
            full_name = find_library(name)
            if full_name is None:
                raise OSError("Cannot load library '%s'" % name)
            name = full_name
        return CDLL(name)

    def get_c_string(c_string):
        return c_string.value

    def get_raw_buffer(buf):
        return buf.raw

    class VoidPointer(object):
        """Model a newly allocated pointer to void"""

        def __init__(self):
            self._p = c_void_p()

        def get(self):
            return self._p

        def address_of(self):
            return byref(self._p)

    backend = "ctypes"


class SmartPointer(object):
    """Class to hold a non-managed piece of memory"""

    def __init__(self, raw_pointer, destructor):
        self._raw_pointer = raw_pointer
        self._destructor = destructor

    def get(self):
        return self._raw_pointer

    def release(self):
        rp, self._raw_pointer = self._raw_pointer, None
        return rp

    def __del__(self):
        try:
            if self._raw_pointer is not None:
                self._destructor(self._raw_pointer)
                self._raw_pointer = None
        except AttributeError:
            pass


def load_pycryptodome_raw_lib(name, cdecl):
    """Load a shared library and return a handle to it.
    @name,  the name of the library expressed as a PyCryptodome module,
            for instance Crypto.Cipher._raw_cbc.
    @cdecl, the C function declarations.
    """

    split = name.split(".")
    dir_comps, basename = split[:-1], split[-1]
    for ext in extension_suffixes:
        try:
            return load_lib(pycryptodome_filename(dir_comps, basename + ext),
                            cdecl)
        except OSError:
            pass
    raise OSError("Cannot load native module '%s'" % name)


def expect_byte_string(data):
    if not byte_string(data) and not isinstance(data, Array):
        raise TypeError("Only byte strings can be passed to C code")

















from Crypto.Cipher import AES
from Crypto.Util.number import *
import os
import json
from binascii import unhexlify
from Crypto.Util.py3compat import bord, _copy_bytes
from Crypto.Util._raw_api import is_buffer
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Hash import BLAKE2s
from Crypto.Random import get_random_bytes
#from Crypto.Util._raw_api import (load_pycryptodome_raw_lib, VoidPointer,
                                  #create_string_buffer, get_raw_buffer,
                                  #SmartPointer, c_size_t, c_uint8_ptr)
from Crypto.Util._raw_api import (c_size_t, c_uint8_ptr)
from Crypto.Util import _cpu_features



class _GHASH(object):
    """GHASH function defined in NIST SP 800-38D, Algorithm 2.
    If X_1, X_2, .. X_m are the blocks of input data, the function
    computes:
       X_1*H^{m} + X_2*H^{m-1} + ... + X_m*H
    in the Galois field GF(2^256) using the reducing polynomial
    (x^128 + x^7 + x^2 + x + 1).
    """

    def __init__(self, subkey, ghash_c):
        assert len(subkey) == 16

        self.ghash_c = ghash_c

        self._exp_key = VoidPointer()
        result = ghash_c.ghash_expand(c_uint8_ptr(subkey),
                                      self._exp_key.address_of())
        if result:
            raise ValueError("Error %d while expanding the GHASH key" % result)

        self._exp_key = SmartPointer(self._exp_key.get(),
                                     ghash_c.ghash_destroy)

        # create_string_buffer always returns a string of zeroes
        self._last_y = create_string_buffer(16)

    def update(self, block_data):
        assert len(block_data) % 16 == 0

        result = self.ghash_c.ghash(self._last_y,
                                    c_uint8_ptr(block_data),
                                    c_size_t(len(block_data)),
                                    self._last_y,
                                    self._exp_key.get())
        if result:
            raise ValueError("Error %d while updating GHASH" % result)

        return self

    def digest(self):
        return get_raw_buffer(self._last_y)


# C API by module implementing GHASH
_ghash_api_template = """
    int ghash_%imp%(uint8_t y_out[16],
                    const uint8_t block_data[],
                    size_t len,
                    const uint8_t y_in[16],
                    const void *exp_key);
    int ghash_expand_%imp%(const uint8_t h[16],
                           void **ghash_tables);
    int ghash_destroy_%imp%(void *ghash_tables);
"""

def _build_impl(lib, postfix):
    from collections import namedtuple

    funcs = ( "ghash", "ghash_expand", "ghash_destroy" )
    GHASH_Imp = namedtuple('_GHash_Imp', funcs)
    try:
        imp_funcs = [ getattr(lib, x + "_" + postfix) for x in funcs ]
    except AttributeError:      # Make sphinx stop complaining with its mocklib
        imp_funcs = [ None ] * 3
    params = dict(zip(funcs, imp_funcs))
    return GHASH_Imp(**params)

def _get_ghash_clmul():
    """Return None if CLMUL implementation is not available"""

    if not _cpu_features.have_clmul():
        return None
    try:
        api = _ghash_api_template.replace("%imp%", "clmul")
        lib = load_pycryptodome_raw_lib("Crypto.Hash._ghash_clmul", api)
        result = _build_impl(lib, "clmul")
    except OSError:
        result = None
    return result
_ghash_clmul = _get_ghash_clmul()

ghash_c = _ghash_clmul



key = b"goodhashGOODHASH"
randomBytes = os.urandom(16).hex()
n1 = ('{"token": "' + randomBytes + '", "admin": false}').encode()
n2 = ('{"token": "' + randomBytes + '", "admin": true }').encode()
n1 = b'{"token": "d3271b732403d742fa1e617d24c741c8", "admin": false}'
n2 = b'{"token": "d3271\xef\xd6\xd8j\xcb\xb0\xdd\x07y2\xeb;.\x1f\r\'17d24c741c8", "admin": true }'
#print(f"nonce 1 is {n1}")
#print(f"nonce 2 is {n2}")


def getJ0(nonce):
    hash_subkey = AES.new(key, AES.MODE_ECB).encrypt(b'\x00'*16)

    fill = (16 - (len(nonce) % 16)) % 16 + 8
    ghash_in = (nonce +
                b'\x00' * fill +
                long_to_bytes(8 * len(nonce), 8))

    j0 = _GHASH(hash_subkey, ghash_c).update(ghash_in).digest()
    #print(f"j0 is {j0}")
    return j0


j0 = getJ0(n1)
j0 = getJ0(n2)

nonce_ctr = j0[:12]
iv_ctr = (bytes_to_long(j0) + 1) & 0xFFFFFFFF
cipher = AES.new(key, AES.MODE_CTR, initial_value=iv_ctr, nonce=nonce_ctr)

ciphertext = cipher.encrypt(b'\0'*32)
#print(f"ciphertext is {ciphertext}")


def digest(nonce):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    enc, tag = cipher.encrypt_and_digest(b"\0" * 32)
    #print(f"enc is {enc}")
    return enc + tag

#digest(nonce)

digest(n1)
digest(n2)