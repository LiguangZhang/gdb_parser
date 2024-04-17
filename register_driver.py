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

global_path = os.path.dirname(os.path.abspath(__file__))
sys.path.append(global_path)
import reg_parser
import freertos_parser
import freertos_class
import reg_class

class reg_help(gdb.Command):

    def __init__(self):
        gdb.Command.__init__(self, 'reghelp', gdb.COMMAND_OBSCURE)

    def invoke(self, arg, from_tty):
        reg_parser.help()


class reg_version(gdb.Command):

    def __init__(self):
        gdb.Command.__init__(self, 'regversion', gdb.COMMAND_OBSCURE)

    def invoke(self, arg, from_tty):
        reg_parser.version()

class reg_dump_ip(gdb.Command):
    def __init__(self):
        gdb.Command.__init__(self, 'rdip', gdb.COMMAND_OBSCURE)
        self.proc = gdb.inferiors()[0]

    def invoke(self, arg, from_tty):
        try:
            reg_parser.dump_ip(arg)
        except Exception as e:
            traceback.print_exc()

class reg_dump_ip_all(gdb.Command):
    def __init__(self):
        gdb.Command.__init__(self, 'rdipa', gdb.COMMAND_OBSCURE)
        self.proc = gdb.inferiors()[0]

    def invoke(self, arg, from_tty):
        try:
            reg_parser.dump_ip_all()
        except Exception as e:
            traceback.print_exc()

class dump_memory(gdb.Command):
    def __init__(self):
        gdb.Command.__init__(self, 'dm', gdb.COMMAND_OBSCURE)
        self.proc = gdb.inferiors()[0]

    def invoke(self, arg, from_tty):
        try:
            reg_parser.dump_memory(arg)
        except Exception as e:
            traceback.print_exc()

class dump_all_task(gdb.Command):
    def __init__(self):
        gdb.Command.__init__(self, 'dta', gdb.COMMAND_OBSCURE)
        self.proc = gdb.inferiors()[0]

    def invoke(self, arg, from_tty):
        try:
            freertos_parser.dump_tasks()
        except Exception as e:
            traceback.print_exc()

class dump_task_stack(gdb.Command):
    def __init__(self):
        gdb.Command.__init__(self, 'ds', gdb.COMMAND_OBSCURE)
        self.proc = gdb.inferiors()[0]

    def invoke(self, arg, from_tty):
        try:
            freertos_parser.dump_task_stack(arg)
        except Exception as e:
            traceback.print_exc()

class dump_all_task_clear_cache(gdb.Command):
    def __init__(self):
        gdb.Command.__init__(self, 'dtc', gdb.COMMAND_OBSCURE)
        self.proc = gdb.inferiors()[0]

    def invoke(self, arg, from_tty):
        try:
            freertos_parser.dump_tasks_clear_cache()
        except Exception as e:
            traceback.print_exc()

class dump_task(gdb.Command):
    def __init__(self):
        gdb.Command.__init__(self, 'dt', gdb.COMMAND_OBSCURE)
        self.proc = gdb.inferiors()[0]

    def invoke(self, arg, from_tty):
        try:
            freertos_parser.dump_task(arg)
        except Exception as e:
            traceback.print_exc()

class dump_list(gdb.Command):
    def __init__(self):
        gdb.Command.__init__(self, 'dl', gdb.COMMAND_OBSCURE)
        self.proc = gdb.inferiors()[0]

    def invoke(self, arg, from_tty):
        try:
            freertos_parser.dump_list(arg)
        except Exception as e:
            traceback.print_exc()

reg_help()
reg_version()
reg_dump_ip()
reg_dump_ip_all()
dump_all_task()
dump_task()
dump_all_task_clear_cache()
dump_task_stack()
dump_list()
dump_memory()
reg_parser.parse_cfg()
