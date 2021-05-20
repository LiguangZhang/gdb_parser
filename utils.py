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

import binascii

def assemble_table(t_list):
    if len(t_list) < 2:
        print("invalid table format")
        return
    header_t = t_list[0]
    items = len(header_t)
    # caculate max item length
    len_of_items = [len(str(v)) for v in header_t]
    for line in t_list[1:]:
        for index, v in enumerate(line):
            len_of_items[index] = max(len(str(v)), len_of_items[index])

    output = ""
    for i, h in enumerate(header_t):
        output += h
        output += " " * 4 + " " * (len_of_items[i] - len(h))
    output += '\n'
    output += '-' * (sum(len_of_items) + 4 * len(len_of_items))
    output += '\n'
    for line in t_list[1:]:
        if(line[0] == "--"):
            output += '-' * (sum(len_of_items) + 4 * len(len_of_items)) + '\n'
            continue
        elif(line[0] == "==" and len(line) > 1):
            output += '=' * (sum(len_of_items)/2) + line[1] + '='*(sum(len_of_items)/2 - len(line[1])) + '=' * (4 * len(len_of_items))  + '\n'
            continue
        for i, v in enumerate(line):
            output += str(v)
            output += " " * 4 + " " * (len_of_items[i] - len(str(v)))
        output += '\n'
    output += '\n'
    return output


def big_small_end_convert(data):
    return binascii.hexlify(binascii.unhexlify(data)[::-1])


def to_lendian_ba(data):
    return binascii.unhexlify(big_small_end_convert(data))


def read_addr_byte(addr, offset):
    return read_addr_bytes(addr, offset, 1)


def read_addr_half_byte_l(addr, offset):
    symbol_addr_byte_hex = read_addr_bytes(addr, offset, 1)
    return symbol_addr_byte_hex[1]


def read_addr_half_byte_h(addr, offset):
    symbol_addr_byte_hex = read_addr_bytes(addr, offset, 1)
    return symbol_addr_byte_hex[0]


def read_addr_bytes_hex(addr, offset, size):
    symbol_addr_byte_hex = read_addr_bytes(addr, offset, size)
    return hex(int(symbol_addr_byte_hex, 16))


def read_addr_bytes(addr, offset, size):
    symbol_addr_byte_hex = ""
    sub_value = addr[offset:offset+size]
    for v in sub_value[::-1]:
        symbol_addr_byte_hex = symbol_addr_byte_hex + str(v)
    return symbol_addr_byte_hex


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


def to_lendian_list(s):
    result = []
    for i in range(len(s)-1, -1, -2):
        result.append(s[i-1:i+1])
    return result

def search_bytes(mem, search_for_bytes, addr_begin, class_size=None):
    search_for_len = len(search_for_bytes)
    off = 0
    whole_word_len = len(mem)
    matches = []
    while (off + search_for_len <= whole_word_len):
        if mem[off:off+search_for_len] == search_for_bytes:
            found_addr = addr_begin + off
            if class_size:
                matches.append((found_addr, addr_begin +
                                (off//class_size)*class_size))
                print("found ", hex(found_addr), hex(
                    addr_begin + (off//class_size)*class_size))
            else:
                matches.append((found_addr, addr_begin))
                print("found ", hex(found_addr), hex(addr_begin))
            off += search_for_len
        else:
            off += 1
    return matches
