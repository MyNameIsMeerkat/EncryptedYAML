#-----------------------------------------------------------
# Filename      : EncryptedYaml.py
# Description   : Simple wrapper around the PyYaml module that
#                 provides support for encrypting the YAML with blowfish
# Created By    : Rich Smith
# Date Created  : 05-Jan-2014 13:30
# 
# License       : LGPL
#
# (c) Copyright 2014, Rich Smith all rights reserved.
#-----------------------------------------------------------

#
# Useful for there are passwords / API keys in the YAML that you would like
# to offer some data at rest protection to.
#
# This *DOES NOT* offer any level of in-memory protection of the objects during
# or after encryption / decryption.
#

__author__ = "Rich Smith"
__version__ = "0.1"

import types

try:
    import yaml
except:
    print "[-] The yaml module is needed to use encrypted yaml.\nGo to http://pyyaml.org or `pip install PyYaml`"
    raise

## Pure Python Blowfish implementation by Michael Gilfix <mgilfix@eecs.tufts.edu>
from blowfish import Blowfish


ENCRYPTED_YAML_HEADER  = "#EncryptedYaml_BlowFish\n\n"

class BadKeyException(Exception):
    pass

class EncryptedYamlException(Exception):
    pass


def is_data_encrypted(data_to_test):
    """
    Test whether a passed string is encrypted by looking for the magic header.
    Return True if the supplied file object is found to have the ENCRYPTED_YAML_HEADER
    False if not.
    """
    ##Look for our magic header in the first line
    if ENCRYPTED_YAML_HEADER in data_to_test:
        encrypted = True
    else:
        encrypted = False

    return encrypted


def _encrypt_yaml(yaml_stream, key):
    """
    Function that does the encryption of the YAML document with the specified key.
    The stream is always a string object.
    Return the encrypted version of the string with the ENCRYPTED_YAML_HEADER prepended.
    """
    ##Blow the fish
    try:
        bfish = Blowfish(key)
        bfish.initCTR()
        crypto_yaml = bfish.encryptCTR(yaml_stream)

        ##Add in our header to indicate we're encrypted
        crypto_yaml = "%s%s"%(ENCRYPTED_YAML_HEADER, crypto_yaml)

    except Exception, err:
        raise EncryptedYamlException("Problem encrypting the YAML file - %s"%(err))

    return crypto_yaml


def _decrypt_yaml(e_yaml_stream, key):
    """
    Function that does the decryption of the YAML document with the specified key.
    The stream can be any of the types of streams support by the PyYaml module (strings,
    unicode strings, or file objects)
    """
    ##We have to read the file so ensure we can reset it to where it was when passed
    if type(e_yaml_stream) == types.FileType:
        curr_poss   = e_yaml_stream.tell()
        e_yaml_data = e_yaml_stream.read()
    else:
        e_yaml_data = e_yaml_stream

    ##Skip first line as it's the magic header
    pos = e_yaml_data.find("\n\n")
    if pos != -1:
        e_yaml_data = e_yaml_data[pos+2:]

    ##Decrypt stream
    try:
        bfish = Blowfish(key)
        bfish.initCTR()
        yaml_data = bfish.decryptCTR(e_yaml_data)

    except Exception, err:
        raise EncryptedYamlException("Problem decrypting the YAML file - %s"%(err))


    ##Reset read position if stream is a file object
    if type(e_yaml_stream) == types.FileType:
        e_yaml_stream.seek(curr_poss)

    return yaml_data


##Overload the load/dump functions from the yaml module so that the encryption/decryption can take place
## if needed and rely on the PyYaml module to do the YAML side of things
def load(stream, Loader = yaml.loader.Loader, key = None):
    """
    Parse the first YAML document in a stream and produce the corresponding Python object.
    If a key is specified decrypt the YAML document prior to parsing.
    """
    ##If a key is provided we need to attempt decryption of the stream
    if key:
        ##Is encrypted, decrypt stream with supplied key and then pass on
        stream = _decrypt_yaml(stream, key)

    ##Hand off decrypted stream to PyYaml module
    return yaml.load(stream, Loader)


def load_all(stream, Loader = yaml.loader.Loader, key = None):
    """
    Parse all YAML documents in a stream and produce corresponding Python objects.
    If a key is specified decrypt the YAML document prior to parsing.
    """
    ##If a key is provided we need to attempt decryption of the stream
    if key:
        ##Is encrypted, decrypt stream with supplied key and then pass on
        stream = _decrypt_yaml(stream, key)

    ##Hand off decrypted stream to PyYaml module
    return yaml.load_all(stream, Loader)


def safe_load(stream, key = None):
    """
    Parse the first YAML document in a stream and produce the corresponding Python object.
    If a key is specified decrypt the YAML document prior to parsing.
    Resolve only basic YAML tags.
    """
    return load(stream, yaml.loader.SafeLoader, key)


def safe_load_all(stream, key = None):
    """
    Parse all YAML documents in a stream and produce corresponding Python objects.
    If a key is specified decrypt the YAML document prior to parsing.
    Resolve only basic YAML tags.
    """
    return load_all(stream, yaml.loader.SafeLoader, key)


def dump_all(documents, stream = None, Dumper = yaml.dumper.Dumper, key = None,  **kwargs):
    """
    Serialize a sequence of Python objects into a YAML stream & if a key is specified encrypt it.
    If stream is None, return the produced string instead.
    """
    all_yaml = ""

    for data in documents:
        ##If a key value has been passed do not pass the stream argument
        ## so as the unencrypted data does not get written to a file else just
        ## do what has been requested
        if not key:
            return yaml.dump(data, stream = stream, Dumper = Dumper, **kwargs)


        ##Do not pass the stream argument to force the return of a string repr of the yaml rather than a file write
        yaml_obj = yaml.dump(data, Dumper = Dumper, **kwargs)

        ##Do the encryption
        crypto_yaml = _encrypt_yaml(yaml_obj, key)

        ##If a stream was passed write the encrypted data to that stream
        if stream:
            try:
                stream.write(crypto_yaml)
            except Exception, err:
                raise EncryptedYamlException("Problem writing encrypted YAML to specified stream - %s"%(err))

        ##If no stream specified just return the header + crypted bytes
        else:
            all_yaml += crypto_yaml

    ##Either return a string representation or None if a stream was passed
    if stream:
        return None
    else:
        return all_yaml


def dump(data, stream = None, Dumper = yaml.dumper.Dumper, key = None, **kwargs):
    """
    Serialize a Python object into a YAML stream & if a key is specified encrypt it.
    If stream is None, return the produced string instead.
    """
    return dump_all([data], stream, Dumper = Dumper, key = key, **kwargs )


def safe_dump(data, stream = None, key = None, **kwargs):
    """
    Serialize a sequence of Python objects into a YAML stream & if a key is specified encrypt it.
    Produce only basic YAML tags.
    If stream is None, return the produced string instead.
    """
    return dump_all([data], stream = stream, key = key, Dumper = yaml.dumper.SafeDumper, **kwargs)


def safe_dump_all(documents, stream = None, key = None, **kwargs):
    """
    Serialize a Python object into a YAML stream & if a key is specified encrypt it.
    Produce only basic YAML tags.
    If stream is None, return the produced string instead.
    """
    return dump_all(documents, stream, key, Dumper = yaml.dumper.SafeDumper, **kwargs)


if __name__ == "__main__":
    """
    Call main code
    """
    ##Perform some tests
    print "[!] Testing EncryptedYaml..."

    import tempfile

    KEY       = "TESTTEST"

    test_yaml = """
    foo: bar
    bar: 2
    """

    test_obj  = {"foo":"bar", "bar":2}

    ##Test YAML dumps
    ret = dump(test_obj)
    print "[+] String Dump: ", ret

    tmp_fd, tmp_fn = tempfile.mkstemp(dir="/tmp")
    tmp_fo = open(tmp_fn, "r+b")

    ret = dump(test_obj, stream = tmp_fo)
    tmp_fo.close()
    print "[+] File Dump written to: ", tmp_fn

    c_ret = dump(test_obj, key = KEY)
    print "[+] Encrypted String Dump: ", c_ret

    e_tmp_fd, e_tmp_fn = tempfile.mkstemp(dir="/tmp")
    e_tmp_fo = open(e_tmp_fn, "r+b")

    ret = dump(test_obj, stream = e_tmp_fo, key = KEY)
    e_tmp_fo.close()
    print "[+] Encrypted File Dump written to: ", e_tmp_fn


    ##Test YAML loads
    ret = load(test_yaml)
    print "[+] String Load: ",ret

    ##test load yaml file
    tmp_fo = open(tmp_fn, "r+b")
    ret = load(tmp_fo)
    tmp_fo.close()
    print "[+] File Load: ",ret

    ##test load encrypted yaml string
    e_tmp_fo = open(e_tmp_fn, "r+b")
    ret = load(e_tmp_fo.read(), key = KEY)
    print "[+] Encrypted String Load:",ret

    ##test load encrypted yaml file
    e_tmp_fo.seek(0)
    ret = load(e_tmp_fo, key = KEY)
    e_tmp_fo.close()
    print "[+] Encrypted File Load:",ret

    print "[!] Done."