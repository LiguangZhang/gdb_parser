#!/usr/bin/env python2

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
from utils import *


STATE_AVAILABLE = 0
STATE_ALLOCATED = 1
STATE_QUARANTINED = 2

ORIGIN_MALLOC = 0 << 2
ORIGIN_NEW = 1 << 2
ORIGIN_NEW_ARRAY = 2 << 2
ORIGIN_MEMALIGN = 3 << 2

ORIGI_DICT = {
    ORIGIN_MALLOC:      "Malloc",
    ORIGIN_NEW:         "New",
    ORIGIN_NEW_ARRAY:   "NewArray",
    ORIGIN_MEMALIGN:    "Memalign",
}

STATE_DICT = {
    STATE_AVAILABLE:    "Available",
    STATE_ALLOCATED:    "Allocated",
    STATE_QUARANTINED:  "Quarantined",
}


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


def parse_data_rel(raw_out):
    lines = raw_out.split('\n')
    break_line = 0
    for index, line in enumerate(lines):
        if line.find(".data.rel.ro") != -1:
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

    print(sorted(elf_d))

    for k, v in elf_d.items():
        if k in addr_d:
            for i in v:
                if int(addr_d[k].addr_offset, 16) >= int(i[3], 16) and \
                        int(addr_d[k].addr_offset, 16) <                 \
                        int(i[3], 16) + int(i[2], 16):
                    addr_d[k].set_vmap_addr(
                        hex(int(i[0], 16) +
                            int(addr_d[k].addr_offset, 16) - int(i[3], 16)))

    for k, v in addr_d.items():
        print(k)
        print("=======")
        if v.vmap_addr:
            print("vmap_addr: ", v.vmap_addr)


def parse_symbol(gdb_out):
    line_list = gdb_out.split()
    if line_list[1].startswith('<'):
        symbol = line_list[1].lstrip('<').rstrip('>:')
        ln = symbol.find('+')
        lino = 0
        if ln != -1:
            symbol = symbol[:ln]
            lino = symbol[ln+1:]
        cmd = ['c++filt', symbol]
        return RunAndCheckOutput(cmd, verbose=False)


def compare(x, y):
    if len(x[1]) == len(y[1]):
        return 0
    elif len(x[1]) > len(y[1]):
        return 1
    elif len(x[1]) < len(y[1]):
        return -1


class ChunkHeader:
    def __init__(self, classid, addr, state, origi,
                 used_bytes, offset, check_sum):
        self.class_id = classid
        self.addr = addr
        self.state = state
        self.origi = origi
        self.used_bytes = used_bytes
        self.offset = offset
        self.check_sum = check_sum


def parse_chunk_header(addr, use_size=None):
    print("parse_chunk_header ", addr)
    class_id = int(read_addr_byte(addr, 0), 16)
    state_origi = int(read_addr_half_byte_l(addr, 1), 16)
    state = None
    origi = None

    if (state_origi & (1 << 2)) == 0:
        origi = ORIGI_DICT[ORIGIN_MALLOC]

    if (state_origi >> 2) == 0:
        state = STATE_DICT[STATE_AVAILABLE]

    for k, v in ORIGI_DICT.items():
        if state_origi & k:
            origi = v

    for k, v in STATE_DICT.items():
        if state_origi & k:
            state = v

    size_or_unused_bytes_low = read_addr_half_byte_h(addr, 1)
    size_or_unused_bytes_high = read_addr_bytes(addr, 2, 2)
    size_or_unused_bytes = int(
        size_or_unused_bytes_low, 16) + int(size_or_unused_bytes_high, 16)*16
    if use_size:
        used_bytes = use_size - size_or_unused_bytes
    else:
        used_bytes = size_or_unused_bytes

    offset = read_addr_bytes_hex(addr, 4, 2)
    check_sum = read_addr_bytes_hex(addr, 6, 2)

    return ChunkHeader(class_id, addr, state, origi,
                       used_bytes, offset, check_sum)


def addr_value_convert(hex_value):
    # base 16 hex_value, size 16
    if(hex_value.startswith("0x")):
        hex_value = hex_value[2:]
    xb_list = []
    v_size = len(hex_value)
    if v_size != 16:
        padding = '0000000000000000'
        hex_value = padding[:16-v_size] + hex_value
    for i in range(8):
        xb_list.append(hex_value[16-(i+1)*2: 16-i*2])
    return xb_list


def parse_addr_value_header(hex_value, arch='64'):
    xb_list = addr_value_convert(hex_value)
    header = parse_chunk_header(xb_list)
    Classes = Classes_64 if arch == '64' else Classes_32
    if not Classes or header.class_id == 0:
        table = [("class_id", "state", "origi", "unused_bytes", "check_sum")]
        table.append((header.class_id, header.state, header.origi,
                      header.used_bytes, header.check_sum))
        print(assemble_table(table))
    else:
        table = [("class_id", "class_size", "state",
                  "origi", "used_bytes", "check_sum")]
        table.append((header.class_id, Classes[header.class_id-1],
                      header.state,
                      header.origi,
                      header.used_bytes,
                      header.check_sum))
        print(assemble_table(table))


def use_help():
    help_doc = """
    h <addr_value> <arch>: parse allocated memory unit chunk header
                           <addr_value> address value of header ' gdb x/a addr'
                           <arch> 32 or 64 for class_size identify
  """
    print(help_doc)


# search in size_class_map.h AndroidSizeClassConfig
# static constexpr u32 Classes[], pls distinguish between 32-bit and 64-bit
Classes_64 = [
    0x00020, 0x00030, 0x00040, 0x00050, 0x00060, 0x00070, 0x00090, 0x000b0,
    0x000c0, 0x000e0, 0x00120, 0x00160, 0x001c0, 0x00250, 0x00320, 0x00450,
    0x00670, 0x00830, 0x00a10, 0x00c30, 0x01010, 0x01210, 0x01bd0, 0x02210,
    0x02d90, 0x03790, 0x04010, 0x04810, 0x05a10, 0x07310, 0x08210, 0x10010,
    0x18010, 0x20010, 0x28010, 0x30010, 0x38010, 0x40010,
]

Classes_32 = [
    0x00020, 0x00030, 0x00040, 0x00050, 0x00060, 0x00070, 0x00080, 0x00090,
    0x000a0, 0x000b0, 0x000c0, 0x000e0, 0x000f0, 0x00110, 0x00120, 0x00130,
    0x00150, 0x00160, 0x00170, 0x00190, 0x001d0, 0x00210, 0x00240, 0x002a0,
    0x00330, 0x00370, 0x003a0, 0x00400, 0x00430, 0x004a0, 0x00530, 0x00610,
    0x00730, 0x00840, 0x00910, 0x009c0, 0x00a60, 0x00b10, 0x00ca0, 0x00e00,
    0x00fb0, 0x01030, 0x01130, 0x011f0, 0x01490, 0x01650, 0x01930, 0x02010,
    0x02190, 0x02490, 0x02850, 0x02d50, 0x03010, 0x03210, 0x03c90, 0x04090,
    0x04510, 0x04810, 0x05c10, 0x06f10, 0x07310, 0x08010, 0x0c010, 0x10010,
]

if __name__ == "__main__":
    cmds = sys.argv[1:]
    if cmds[0] == "h" and len(cmds) == 2:
        parse_addr_value_header(cmds[1])
    elif cmds[0] == "h" and len(cmds) == 3:
        parse_addr_value_header(cmds[1], cmds[2])
    elif cmds[0] == "-h":
        use_help()
