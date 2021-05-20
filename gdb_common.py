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


import gdb


# cache
cache_d = {}
cache_d["offsets"] = {}
cache_d["sizes"] = {}
cache_d["values"] = {}


def symbol_int_value(symbol):
    return convert2int(get_value(symbol))


def convert2int(val):
    value = str(val).split(" ")[-1]
    return int(value, 16) if value.startswith('0x') else int(value)


def arch_dword_size():
    global cache_d
    if "dword_size" in cache_d:
        return cache_d["dword_size"]
    abi = gdb.selected_frame().architecture().name()
    cache_d["dword_size"] = 8
    if abi is "aarch64":
        cache_d["dword_size"] = 8
    elif abi is "arm":
        cache_d["dword_size"] = 4
    return cache_d["dword_size"]


def offset_of(s_name, m_name):
    global cache_d
    key = "{}.{}".format(s_name, m_name)
    if key not in cache_d["offsets"]:
        expr = '(size_t)&((({} *)0)->{}) - (size_t)(({} *)0)'.format(
               s_name, m_name, s_name)
        cache_d["offsets"][key] = convert2int(gdb.parse_and_eval(expr))
    return cache_d["offsets"][key]


def type_size(type_name):
    global cache_d
    if type_name not in cache_d["sizes"]:
        cache_d["sizes"][type_name] = convert2int(
            gdb.parse_and_eval('sizeof({})'.format(type_name)))
    return cache_d["sizes"][type_name]


def get_value(symbol):
    global cache_d

    if symbol not in cache_d["values"]:
        cache_d["values"][symbol] = gdb.parse_and_eval(symbol)
    return cache_d["values"][symbol]


def read_memory(addr, size):
    mem = gdb.selected_inferior().read_memory(addr, size)
    le_mem = 0
    for i, b in enumerate(mem):
        le_mem |= (ord(b) << i * 8)
    return le_mem


def read_bytes(addr, size):
    return bytearray(gdb.selected_inferior().read_memory(addr, size))


def read_word(addr):
    mem = read_bytes(addr, arch_dword_size())
    return dword_in_buf(mem)


def dword_in_buf(buf, off=0):
    return bytes2num(buf, arch_dword_size()+off, off)

def clear_cache():
    cache_d.clear()

def read_addr_width(addr, off, width):
    if cache_d.has_key(addr):
        gdb_out = cache_d[addr]
    else:
        gdb_out = gdb.execute("x/t {}".format(addr), to_string=True);
    number = gdb_out.split("\t")[-1].rstrip("\n")
    return number[len(number)-off-width:len(number)-off]

def bytes2num(vbytes, nbytes, off=0):
    buf = vbytes[off:]
    num = 0
    for i in range(0, nbytes):
        num |= (buf[i] << i * 8)
    return num


def read_struct_member_value(buf, s_name, m_name, size):
    if size > arch_dword_size():
        return None
    offset = offset_of(s_name, m_name)
    val = bytes2num(buf, size, offset)
    return val
