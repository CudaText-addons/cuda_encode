import sys
import os
from unicodedata import normalize
from cudatext import *
from .lib_encode import *
from .rot_proc import *
from . import format_proc

from cudax_lib import get_translation
_ = get_translation(__file__)  # I18N


format_proc.INI = 'cuda_encode.ini'
format_proc.MSG = _('[Encode] ')


def do(text, class_name):
    msg = class_name.__name__
    suffix = 'Command'
    if msg.endswith(suffix):
        msg = msg[:-len(suffix)]
    format_proc.MSG = _('[Encode %s] ') % msg
    
    c = class_name()
    text = c.encode(text)
    del c
    return text


class Command:

    def html_entitize(self)       : format_proc.run( lambda text: do(text, HtmlEntitizeCommand) )
    def html_deentitize(self)     : format_proc.run( lambda text: do(text, HtmlDeentitizeCommand) )
    def css_escape(self)          : format_proc.run( lambda text: do(text, CssEscapeCommand) )
    def css_unescape(self)        : format_proc.run( lambda text: do(text, CssUnescapeCommand) )
    def xml_entitize(self)        : format_proc.run( lambda text: do(text, XmlEntitizeCommand) )
    def xml_deentitize(self)      : format_proc.run( lambda text: do(text, XmlDeentitizeCommand) )
    def safe_html_entitize(self)  : format_proc.run( lambda text: do(text, SafeHtmlEntitizeCommand) )
    def safe_html_deentitize(self): format_proc.run( lambda text: do(text, SafeHtmlDeentitizeCommand) )

    def json_escape(self)         : format_proc.run( lambda text: do(text, JsonEscapeCommand) )
    def json_unescape(self)       : format_proc.run( lambda text: do(text, JsonUnescapeCommand) )
    def url_encode(self)          : format_proc.run( lambda text: do(text, UrlEncodeCommand) )
    def url_decode(self)          : format_proc.run( lambda text: do(text, UrlDecodeCommand) )

    def md5_encode(self)          : format_proc.run( lambda text: do(text, Md5EncodeCommand) )
    def sha256_encode(self)       : format_proc.run( lambda text: do(text, Sha256EncodeCommand) )
    def sha512_encode(self)       : format_proc.run( lambda text: do(text, Sha512EncodeCommand) )

    def base64_encode(self)       : format_proc.run( lambda text: do(text, Base64EncodeCommand) )
    def base64_decode(self)       : format_proc.run( lambda text: do(text, Base64DecodeCommand) )
    def base32_encode(self)       : format_proc.run( lambda text: do(text, Base32EncodeCommand) )
    def base32_decode(self)       : format_proc.run( lambda text: do(text, Base32DecodeCommand) )
    def base16_encode(self)       : format_proc.run( lambda text: do(text, Base16EncodeCommand) )
    def base16_decode(self)       : format_proc.run( lambda text: do(text, Base16DecodeCommand) )

    def quopri_encode(self)       : format_proc.run( lambda text: do(text, QuoPriEncodeCommand) )
    def quopri_decode(self)       : format_proc.run( lambda text: do(text, QuoPriDecodeCommand) )

    def uniescape_encode(self)    : format_proc.run( lambda text: do(text, UnicodeEscapeEncodeCommand) )
    def uniescape_decode(self)    : format_proc.run( lambda text: do(text, UnicodeEscapeDecodeCommand) )

    def escape_regex(self)        : format_proc.run( lambda text: do(text, EscapeRegexCommand) )
    def escape_like(self)         : format_proc.run( lambda text: do(text, EscapeLikeCommand) )

    def dec_hex(self)             : format_proc.run( lambda text: do(text, DecHexCommand) )
    def hex_dec(self)             : format_proc.run( lambda text: do(text, HexDecCommand) )
    #def unicode_hex(self)         : format_proc.run( lambda text: do(text, UnicodeHexCommand) )
    #def hex_unicode(self)         : format_proc.run( lambda text: do(text, HexUnicodeCommand) )

    def rot13(self)        : format_proc.run(rot13)
    def rot18(self)        : format_proc.run(rot18)
    def rot47(self)        : format_proc.run(rot47)

    def uni_norm_nfc(self)        : format_proc.run( lambda text: normalize('NFC', text) )
    def uni_norm_nfd(self)        : format_proc.run( lambda text: normalize('NFD', text) )
    def uni_norm_nfkc(self)       : format_proc.run( lambda text: normalize('NFKC', text) )
    def uni_norm_nfkd(self)       : format_proc.run( lambda text: normalize('NFKD', text) )
