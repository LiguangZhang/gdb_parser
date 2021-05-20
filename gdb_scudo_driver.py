# Copyright 2016 Xiaomi, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import sys
import getopt
import warnings
import traceback
import gdb
import shutil
import time
import datetime
import copy
import tempfile

#global_path = os.path.dirname(os.path.realpath(__file__))
global_path = "/home/mi/workspace/register_parser"
sys.path.append(global_path)
import scudo_parser


class scudo_help(gdb.Command):

    def __init__(self):
        gdb.Command.__init__(self, 'scuhelp', gdb.COMMAND_OBSCURE)

    def invoke(self, arg, from_tty):
        print global_path
        print sys.path
        print "hello world"


class scudo_version(gdb.Command):

    def __init__(self):
        gdb.Command.__init__(self, 'scuversion', gdb.COMMAND_OBSCURE)

    def invoke(self, arg, from_tty):
        scudo_parser.version()


class scudo_parse(gdb.Command):

    def __init__(self):
        gdb.Command.__init__(self, 'scuparse', gdb.COMMAND_OBSCURE)
        self.proc = gdb.inferiors()[0]

    def invoke(self, arg, from_tty):
        try:
            scudo_parser.parse()
        except Exception as e:
            traceback.print_exc()


class scudo_chunks(gdb.Command):
    def __init__(self):
        gdb.Command.__init__(self, 'scuchunks', gdb.COMMAND_OBSCURE)
        self.proc = gdb.inferiors()[0]

    def invoke(self, arg, from_tty):
        try:
            scudo_parser.dump_chunks(arg)
        except Exception as e:
            traceback.print_exc()


class scudo_perclass(gdb.Command):
    def __init__(self):
        gdb.Command.__init__(self, 'scuperclass', gdb.COMMAND_OBSCURE)
        self.proc = gdb.inferiors()[0]

    def invoke(self, arg, from_tty):
        try:
            scudo_parser.dump_perclasses()
        except Exception as e:
            traceback.print_exc()


class scudo_secondary(gdb.Command):
    def __init__(self):
        gdb.Command.__init__(self, 'scusecondary', gdb.COMMAND_OBSCURE)
        self.proc = gdb.inferiors()[0]

    def invoke(self, arg, from_tty):
        try:
            scudo_parser.dump_secondary()
        except Exception as e:
            traceback.print_exc()


class scudo_chunk_info(gdb.Command):
    def __init__(self):
        gdb.Command.__init__(self, 'scuchunkinfo', gdb.COMMAND_OBSCURE)
        self.proc = gdb.inferiors()[0]

    def invoke(self, arg, from_tty):
        try:
            scudo_parser.dump_chunk_info(arg)
        except Exception as e:
            traceback.print_exc()


class scudo_all_chunks(gdb.Command):
    def __init__(self):
        gdb.Command.__init__(self, 'scuachunks', gdb.COMMAND_OBSCURE)
        self.proc = gdb.inferiors()[0]

    def invoke(self, arg, from_tty):
        try:
            scudo_parser.dump_all_chunks(int(arg))
        except Exception as e:
            traceback.print_exc()


class scudo_chunk_search(gdb.Command):
    def __init__(self):
        gdb.Command.__init__(self, 'scusearch', gdb.COMMAND_OBSCURE)
        self.proc = gdb.inferiors()[0]

    def invoke(self, arg, from_tty):
        try:
            scudo_parser.chunk_search(arg)
        except Exception as e:
            traceback.print_exc()


class scudo_data_search(gdb.Command):
    def __init__(self):
        gdb.Command.__init__(self, 'scudsearch', gdb.COMMAND_OBSCURE)
        self.proc = gdb.inferiors()[0]

    def invoke(self, arg, from_tty):
        try:
            scudo_parser.data_search(arg)
        except Exception as e:
            traceback.print_exc()


class scudo_region_info(gdb.Command):
    def __init__(self):
        gdb.Command.__init__(self, 'scuregioninfo', gdb.COMMAND_OBSCURE)
        self.proc = gdb.inferiors()[0]

    def invoke(self, arg, from_tty):
        try:
            scudo_parser.dump_region_infos()
        except Exception as e:
            traceback.print_exc()


class scudo_addr_info(gdb.Command):
    def __init__(self):
        gdb.Command.__init__(self, 'scuaddrinfo', gdb.COMMAND_OBSCURE)
        self.proc = gdb.inferiors()[0]

    def invoke(self, arg, from_tty):
        try:
            scudo_parser.dump_chunk_info(arg, start_from_header=False)
        except Exception as e:
            traceback.print_exc()


class scudo_statistics(gdb.Command):
    def __init__(self):
        gdb.Command.__init__(self, 'scustat', gdb.COMMAND_OBSCURE)
        self.proc = gdb.inferiors()[0]

    def invoke(self, arg, from_tty):
        try:
            scudo_parser.dump_all_chunk_hit_stat(arg)
        except Exception as e:
            traceback.print_exc()


class scudo_classid(gdb.Command):
    def __init__(self):
        gdb.Command.__init__(self, 'scucid', gdb.COMMAND_OBSCURE)
        self.proc = gdb.inferiors()[0]

    def invoke(self, arg, from_tty):
        try:
            scudo_parser.dump_classid(int(arg))
        except Exception as e:
            traceback.print_exc()


scudo_help()
scudo_version()
scudo_parse()
scudo_perclass()
scudo_chunks()
scudo_chunk_info()
scudo_addr_info()
scudo_secondary()
scudo_all_chunks()
scudo_chunk_search()
scudo_region_info()
scudo_statistics()
scudo_classid()
scudo_data_search()
