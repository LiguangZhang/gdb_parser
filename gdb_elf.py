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
import shutil
import time
import datetime
import copy
import tempfile
from collections import defaultdict
import subprocess


class ExternalError(RuntimeError):
    pass


def Run(args, verbose=None, **kwargs):
    if 'stdout' not in kwargs and 'stderr' not in kwargs:
        kwargs['stdout'] = subprocess.PIPE
        kwargs['stderr'] = subprocess.STDOUT
    else:
        pass
    if verbose is not False:
        print("Running: {}".format(args))
    return subprocess.Popen(args, **kwargs)


def RunAndCheckOutput(args, verbose=None, **kwargs):
    proc = Run(args, verbose=verbose, **kwargs)
    output, _ = proc.communicate()
    # Don't log any if caller explicitly says so.
    if verbose is not False and output:
        print("%s", output.rstrip())
    if proc.returncode != 0:
        raise ExternalError(
            "Failed to run command '{}' (exit code {}):\n{}".format(
                args, proc.returncode, output))
    return output


def parse_mapping(raw_out):
    lines = raw_out.split("\n")
    map_items = []
    for line in lines:
        sub_items = line.split()
        map_items.append(tuple(sub_items))
    return map_items


def parse_mapping_tls(map_items):
    d = {}
    for sub_items in map_items:
        if len(sub_items) == 5:
            if sub_items[-1].find("anon:stack_and_tls") != -1:
                thread_name = sub_items[-1].lstrip(
                    '[').rstrip(']').split(":")[-1]
                if thread_name == "main":
                    d[thread_name] = sub_items[1]
                elif int(thread_name):
                    d[thread_name] = sub_items[1]
    return d


def parse_mapping_elf(map_items):
    d = defaultdict(list)
    for sub_items in map_items:
        if len(sub_items) == 5:
            elf_f = SYMBOL_ROOT + sub_items[-1]
            if sub_items[3] == '0x0':
                continue
            if os.path.isfile(elf_f):
                d[elf_f].append(sub_items)
    return d


def parse_data_rel(raw_out):
    lines = raw_out.split('\n')
    break_line = 0
    for index, l in enumerate(lines):
        if l.find(".data.rel.ro") != -1:
            break_line = index
            break
    if break_line:
        data_rel_addr_info = tuple(lines[break_line].split())
        if len(data_rel_addr_info) == 5:
            addr = hex(int(data_rel_addr_info[3], 16))
            data_rel_addr_info = tuple(lines[break_line+1].split())
            size = hex(int(data_rel_addr_info[0], 16))
            return (addr, size)
    return None


class AddrInfo:
    def __init__(self, addr_offset, addr_size):
        self.addr_offset = addr_offset
        self.addr_size = addr_size
        self.vmap_addr = None

    def set_vmap_addr(self, vmap_addr):
        self.vmap_addr = vmap_addr


def read_data_rel(f):
    out = read_elf(f)
    addr_info = parse_data_rel(out)
    if(addr_info):
        return AddrInfo(addr_info[0], addr_info[1])


def read_elf(f):
    cmd = ['aarch64-linux-gnu-readelf', '-S', f]
    out = RunAndCheckOutput(cmd, verbose=False)
    return out


def parse_elf(raw_out):
    map_items = parse_mapping(raw_out)
    d = parse_mapping_tls(map_items)
    print(d)

    elf_d = parse_mapping_elf(map_items)
    addr_d = defaultdict(AddrInfo)
    for k, v in elf_d.items():
        print(k)
        print("===========")
        for i in v:
            print(i)
        addr_info = read_data_rel(k)
        if addr_info:
            addr_d[k] = addr_info
            print(addr_info.addr_offset, addr_info.addr_size)

    for k, v in elf_d.items():
        if k in addr_d:
            for i in v:
                if int(addr_d[k].addr_offset, 16) >= int(i[3], 16) and \
                        (int(addr_d[k].addr_offset, 16) <
                            int(i[3], 16) + int(i[2], 16)):
                    addr_d[k].set_vmap_addr(
                        hex(int(i[0], 16) + int(addr_d[k].addr_offset, 16)
                            - int(i[3], 16)))

    for k, v in addr_d.items():
        print(k)
        print("=======")
        if v.vmap_addr:
            print("vmap_addr: ", v.vmap_addr)
