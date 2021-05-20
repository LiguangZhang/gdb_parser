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

import threading
import time
import gdb
import gdb_common as dbg
import datetime

g_exit_flag = False


class SearchThread (threading.Thread):
    def __init__(self, thread_id, name, start_addr, addr_size, gdb_output):
        threading.Thread.__init__(self)
        self.thread_id = thread_id
        self.name = name
        self.start_addr = start_addr
        self.addr_size = addr_size
        self.gdb_output = gdb_output

    def run(self):
        print "starting " + self.name
        if process_data(self.name, self.start_addr,
                        self.addr_size, self.gdb_output):
            g_exit_flag = True
        print "exiting " + self.name


def print_timestamp():
    ts = time.time()
    st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    print('[parser] %s' % (st))


def process_data(thread_name, start_addr, addr_size, gdb_output):
    global g_search_result
    print("{} searching {} - {}".format(thread_name,
                                        start_addr, start_addr + addr_size))
    for line in gdb_output.split('\n'):
        if g_exit_flag:
            return False
        try:
            if line.find("g_thread_list") != -1:
                base_info = line.split('\t')[0]
                if base_info:
                    base_addr, symbol_info = base_info.split(' ')
                    if(symbol_info.endswith("g_thread_list>:")):
                        print("Found g_thread_list {}".format(base_addr))
                        g_search_result = (base_addr, line.split('\t')[1])
                        return True
        except Exception as e:
            continue
    return False


def process_data(gdb_output):
    global g_search_result
    for line in gdb_output.split('\n'):
        if g_exit_flag:
            return False
        try:
            if line.find("g_thread_list") != -1:
                base_info = line.split('\t')[0]
                if base_info:
                    base_addr, symbol_info = base_info.split(' ')
                    if(symbol_info.endswith("g_thread_list>:")):
                        print("Found g_thread_list {}".format(base_addr))
                        g_search_result = (base_addr, line.split('\t')[1])
                        return True
        except Exception as e:
            continue
    return False


def find_libc_bss():
    raw_out = gdb.execute('info files', to_string=True)
    for line in raw_out.split('\n'):
        if line.find("libc.so") != -1 and line.find(".bss") != -1:
            try:
                begin_addr, _, end_addr, _, section, _, libfile = tuple(
                    line.strip('\t').split(' '))
                if begin_addr.startswith("0x") and end_addr.startswith("0x"):
                    return (begin_addr, end_addr)
            except Exception as e:
                print("Exception", line, e)
                continue
    return None


def parse_libc_bss(start_addr, bss_size):
    if bss_size > 0:
        word_size = dbg.arch_dword_size()
        total_split = 16
        per_bss_scan_size = bss_size / (total_split)
        threads = []
        for i in range(total_split):
            for j in range(0, 16/word_size):
                start_scan_addr = int(start_addr, 16) + \
                    j * word_size + i * per_bss_scan_size
                gdb_output = gdb.execute(
                    'x/{}a {}'.format(per_bss_scan_size/8, start_scan_addr),
                    to_string=True)
                if process_data(gdb_output):
                    return True
    return False


def get_g_thread_list():
    global g_search_result
    g_search_result = None
    result = find_libc_bss()
    if not result:
        return None
    libc_bss_begin_addr, libc_bss_end_addr = result
    bss_size = 0
    if libc_bss_begin_addr and libc_bss_end_addr:
        print("hit bss of libc {} - {}".format(
            libc_bss_begin_addr, libc_bss_end_addr))
        bss_size = int(libc_bss_end_addr, 16) - int(libc_bss_begin_addr, 16)
        print_timestamp()
        parse_libc_bss(libc_bss_begin_addr, bss_size)
        print_timestamp()
        print("g_search result", g_search_result)
        if g_search_result:
            print("Found g_search result", g_search_result)
            base_addr, value = g_search_result
            return int(value, 16)
    return None
