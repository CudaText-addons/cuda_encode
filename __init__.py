import sys
import os
from cudatext import *
from .lib_encode import *
from . import format_proc

format_proc.INI = 'cuda_encode.ini'
format_proc.MSG = '[Encode] '


def do(text, class_name):
    msg = class_name.__name__
    suffix = 'Command'
    if msg.endswith(suffix):
        msg = msg[:-len(suffix)]
    format_proc.MSG = '[Encode %s] ' % msg
    
    c = class_name()
    text = c.encode(text)
    del c
    return text


class Command:
    def html_entitize(self): format_proc.run( lambda text: do(text, HtmlEntitizeCommand) )
