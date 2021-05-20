#!/usr/bin/python2

import sys
import re

global_path = "/home/liguang/work_space/register_parser"
sys.path.append(global_path)

import reg_class
import utils
from reg_parse_cfg import *

def parse_update(name):
    for u in reg_info.unit_list:
        if(u.ip_name == name):
            val = 0xff
            u.update(val)

def dump_info(name):
    parse_update(name)
    table = [("name", "addr", "offset", "value", "group_name", "group_offset")]
    for u in reg_info.unit_list:
        if(u.ip_name == name):
            table.append((u.reg_name, hex(u.addr), u.off_str, u.val, u.g_name, reg_info.group_dict[u.g_name].offset))
    print(utils.assemble_table(table))

def test_read_bytes():
    gdb_output = "0x81003c9f <main+19>:   1157627964"
    number = bin(int(gdb_output.split(" ")[-1]))
    print(number.lstrip('0b'))
    print(number[len(number)-3:])

IP_NAME = ""
GROUP_NAME = ""
parse_cfg()
dump_info("DMA")
#test_read_bytes()