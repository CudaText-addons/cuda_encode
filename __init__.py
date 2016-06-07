import sys
import os
from cudatext import *
from .lib_encode import *
from . import format_proc

format_proc.INI = 'cuda_encode.ini'
format_proc.MSG = '[Encode] '


def do(text, class_name):
    c = class_name()
    text = c.encode(text)
    del c
    return text


def do_html_entitize(text):
    return do(text, HtmlEntitizeCommand)


class Command:
    def html_entitize(self):
        format_proc.run(do_html_entitize)
