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

from __future__ import print_function
import os
import sys
import shutil
import time
import datetime
import copy
import tempfile
import traceback
import ConfigParser
import logging
from scudo_class import *
import gdb
import gdb_elf
from collections import defaultdict
import utils
import bss_search
from gdb_common import *
from utils import *


VERSION = 'v1.0'
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

global_file_path = os.path.dirname(os.path.realpath(__file__))
LOG_FORMAT = ""
# INFO DEBUG WARNING ERROR CRITICAL
logging.basicConfig(format=LOG_FORMAT, level=logging.WARNING)


def version():
    '''Output version number'''

    global VERSION
    print('[parser] parser %s' % (VERSION))


def help():
    '''Details about the commands provided by parser'''

    print('\n[parser] scudo')
    print('[parser] parser %s' % (VERSION))
    print('[parser] scudo-specific commands:')
    print('[parser]   scuperclass \
        : dump info on all available perclass')
    print('[parser]   scuchunks <class_size>  \
        : dump info on all class_size in perclass')
    print('[parser]   scuachunks <class_size> \
        : dump info on all class_size in RegionInfo mapped area')
    print('[parser]   scusearch  <addr>       \
        : search addr in primary perclass regionInfo and secondary')
    print('[parser]   scudsearch  <data>      \
        : search data in heap allocated chunks')
    print('[parser]   scuparse                \
        : parse scudo structures from memory')
    print('[parser]   scusecondary            \
        : dump info of secondary structures')
    print('[parser]   scuaddrinfo <addr>      \
        : dump malloc addr state')
    print('[parser]   scuchunkinfo <addr>     \
        : dump chunk header state')
    print('[parser]   scustat                 \
        : dump allocated chunk statistic information')
    print('[parser]           h               \
        :     hits in descending order')
    print('[parser]              s            \
        :     total size in descending order')
    print('[parser]              d            \
        :             in detail')


def dump_chunks(classsize):
    logging.warning("dump chunks {}".format(classsize))

    global scuheap
    if not scuheap:
        logging.error("pls run scuparse first")
        return
    table = [("index", "tid", "chunk_addr", "class_size",
              "classid", "state", "origin", "used_bytes")]
    class_size = int(classsize)
    tab = "   "
    for pc in scuheap.perclass_array:
        if class_size == pc.class_size and pc.class_id:
            for i, chunk_header in enumerate(pc.chunk_list):
                if i == len(pc.chunk_list) - 1:
                    if not chunk_header:
                        table.append(
                            (tab+".", ".", ".", ".", ".", ".", ".", "."))
                        table.append(
                            (tab + str(i), pc.tid, '0x0', pc.class_size,
                             "None", "None", "None", "None"))
                if not chunk_header:
                    continue
                if chunk_header.addr == '0x0':
                    continue
                if i == pc.count - 1:
                    index = "-->" + str(i)
                else:
                    index = tab + str(i)
                table.append((index, pc.tid, chunk_header.addr, pc.class_size,
                              chunk_header.class_id, chunk_header.state,
                              chunk_header.origi, chunk_header.used_bytes))

    print(assemble_table(table))


def dump_perclasses():
    global scuheap
    if not scuheap:
        logging.error("pls run scuparse first")
        return

    table = [("class_id", "tid", "count", "max_count", "class_size")]
    for index, perclass in enumerate(scuheap.perclass_array):
        class_id = index % scuheap.num_classes
        table.append((class_id, perclass.tid, perclass.count,
                      perclass.max_count, perclass.class_size))
    print(assemble_table(table))

    table = [("tid", "tsd_ind", "tsd_addr")]
    for tid_info in scuheap.tid_infos:
        table.append((tid_info.tid, tid_info.tsd_ind, tid_info.tsd_addr))
    print(assemble_table(table))


def data_search(search_for):
    global scuheap

    if not scuheap:
        logging.error("pls run scuparse first")
        return

    search_for = search_for.lstrip('0x')
    matches = []

    logging.warning("search for {}".format(search_for))

    search_for_hex = utils.to_lendian_ba(search_for)
    search_for_bytes = bytearray(search_for_hex)
    logging.warning("search for {}".format(search_for_bytes))

    perclas_array_size = symbol_int_value('Allocator.Primary.NumClasses')
    for index in range(1, perclas_array_size):
        RegionBeg = int(scuheap.region_info_array[index].region_beg, 16)
        AllocatedUser = int(
            scuheap.region_info_array[index].allocated_user, 16)
        mem = read_bytes(RegionBeg, AllocatedUser)
        matches.extend(utils.search_bytes(
            mem, search_for_bytes,
            RegionBeg, scuheap.perclass_array[index].class_size)
        )

    for use_block_item in scuheap.secondary.in_use_blocks_list:
        use_block = use_block_item.large_block
        user_addr = int(use_block.user_start_addr, 16)
        map_user_size = int(use_block.block_end, 16) - user_addr - 1
        mem = read_bytes(user_addr, map_user_size)
        matches.extend(utils.search_bytes(mem, search_for_bytes, user_addr))

    for cache_block_item in scuheap.secondary.cache_entry_list:
        cache_block = cache_block_item.large_block
        user_addr = int(cache_block.user_start_addr, 16)
        map_user_size = int(cache_block.block_end, 16) - user_addr - 1
        mem = read_bytes(user_addr, map_user_size)
        matches.extend(utils.search_bytes(mem, search_for_bytes, user_addr))

    for found_addr, addr_begin in matches:
        if addr_begin in scuheap.user_addr_map:
            try:
                large_block = scuheap.user_addr_map[addr_begin].large_block
                table = [("found_addr", "BlockEnd", "MapBase", "MapSize",
                          "state", "origi", "used_bytes", "chunkaddr",
                          "user_addr_start", "check_sum",
                          "symbol_addr", "symbol_info")]
                table.append((hex(found_addr), large_block.block_end,
                              large_block.map_base, large_block.map_size,
                              large_block.chunk_header.state,
                              large_block.chunk_header.origi,
                              large_block.chunk_header.used_bytes,
                              large_block.chunk_header.addr,
                              large_block.chunk_header.user_addr,
                              large_block.chunk_header.check_sum,
                              large_block.chunk_header.symbol_addr,
                              large_block.chunk_header.symbol_info))
                print(assemble_table(table))
            except Exception as e:
                header = scuheap.user_addr_map[addr_begin]
                table = [("found_addr", "chunk_addr", "class_size", "class_id",
                          "state", "origi", "used_bytes", "user_addr_start",
                          "check_sum", "symbol_addr", "symbol_info")]
                table.append((hex(found_addr), header.addr,
                              scuheap.perclass_array[header.class_id]
                              .class_size,
                              header.class_id,
                              header.state,
                              header.origi,
                              header.used_bytes,
                              header.user_addr,
                              header.check_sum,
                              header.symbol_addr,
                              header.symbol_info))
                print(assemble_table(table))
        else:
            chunk_search(hex(found_addr))


def chunk_search(addr):
    global scuheap

    if not scuheap:
        logging.error("pls run scuparse first")
        return

    header_size = scuheap.chunk_header_size

    chunk_start_hex = hexadd(addr, -header_size)

    address = int(chunk_start_hex, 16)

    logging.warning("search in primary perclass...")
    for pc in scuheap.perclass_array:
        for index, chunk_header in enumerate(pc.chunk_list):
            if not chunk_header:
                continue
            if address < int(chunk_header.addr, 16) + pc.class_size and \
                    address >= int(chunk_header.addr, 16):
                table = [("index", "tid", "chunk_addr", "class_size",
                          "class_id", "state", "origi", "used_bytes",
                          "user_addr_start", "check_sum",
                          "symbol_addr", "symbol_info")]
                table.append((index, pc.tid, chunk_header.addr, pc.class_size,
                              chunk_header.class_id,
                              chunk_header.state,
                              chunk_header.origi,
                              chunk_header.used_bytes,
                              chunk_header.user_addr,
                              chunk_header.check_sum,
                              chunk_header.symbol_addr,
                              chunk_header.symbol_info))
                print(assemble_table(table))
                return

    logging.warning("search in secondary used...")
    for use_block_item in scuheap.secondary.in_use_blocks_list:
        use_block = use_block_item.large_block
        if address <= int(hexadd(use_block.block_end, -header_size), 16) and \
                address >= int(use_block.chunk_header.addr, 16):
            table = [("Prev", "Next", "BlockEnd", "MapBase", "MapSize",
                      "state", "origi", "used_bytes",
                      "chunkaddr", "user_addr_start", "check_sum",
                      "symbol_addr", "symbol_info")]
            table.append((use_block_item.l_prev,
                          use_block_item.l_next,
                          use_block.block_end,
                          use_block.map_base,
                          use_block.map_size,
                          use_block.chunk_header.state,
                          use_block.chunk_header.origi,
                          use_block.chunk_header.used_bytes,
                          use_block.chunk_header.addr,
                          use_block.chunk_header.user_addr,
                          use_block.chunk_header.check_sum,
                          use_block.chunk_header.symbol_addr,
                          use_block.chunk_header.symbol_info))
            print(assemble_table(table))
            return

    logging.warning("search in secondary cache...")
    for cache_entry_item in scuheap.secondary.cache_entry_list:
        cache_entry = cache_entry_item.large_block
        if address <= int(hexadd(cache_entry.block_end, -header_size), 16) \
                and address >= int(cache_entry.chunk_header_addr, 16):
            header = parse_chunk_header(cache_entry.chunk_header_addr)
            table = [("BlockAddr", "BlockEnd", "MapBase", "MapSize",
                      "state", "origi", "used_bytes", "user_addr_start",
                      "check_sum", "symbol_addr", "symbol_info")]
            table.append((cache_entry.block_addr,
                          cache_entry.block_end,
                          cache_entry.map_base,
                          cache_entry.map_size,
                          cache_entry.chunk_header.state,
                          cache_entry.chunk_header.origi,
                          cache_entry.chunk_header.used_bytes,
                          cache_entry.chunk_header.user_addr,
                          cache_entry.chunk_header.check_sum,
                          cache_entry.chunk_header.symbol_addr,
                          cache_entry.chunk_header.symbol_info))
            print(assemble_table(table))
            return

    logging.warning("search in primary RegionInfo mapped user...")
    perclas_array_size = symbol_int_value('Allocator.Primary.NumClasses')
    class_id = -1
    for index in range(perclas_array_size):
        RegionBeg = int(scuheap.region_info_array[index].region_beg, 16)
        RegionEnd = RegionBeg + \
            int(scuheap.region_info_array[index].allocated_user,
                16) - header_size
        if address >= RegionBeg and address < RegionEnd:
            class_id = index
            break
    if class_id != -1:
        index = class_id
        logging.warning("locate region...")
        dump_region_info(class_id)
        class_size = scuheap.perclass_array[index].class_size
        header_list = parse_allocated_chunks(class_size)
        for header_index, header in enumerate(header_list):
            if (address < int(header.addr, 16) + (class_size - header_size)) \
                    and (address >= int(header.addr, 16)):
                table = [("index", "chunk_addr", "class_size",
                          "class_id", "state", "origi",
                          "used_bytes", "user_addr_start",
                          "check_sum", "symbol_addr", "symbol_info")]
                table.append((header_index, header.addr, class_size,
                              header.class_id, header.state,
                              header.origi, header.used_bytes,
                              header.user_addr, header.check_sum,
                              header.symbol_addr, header.symbol_info))
                print(assemble_table(table))
                return

    logging.error("{} not a valid pointer".format(addr))


def dump_chunk_info(chunk_addr, start_from_header=True):
    global scuheap
    if not scuheap:
        logging.error("pls run scuparse first")
        return

    header_size = scuheap.chunk_header_size
    if start_from_header:
        chunk_start_hex = chunk_addr
    else:
        chunk_start_hex = hexadd(chunk_addr, -header_size)

    logging.warning("from perclass...")
    FOUND = False
    for pc in scuheap.perclass_array:
        for index, chunk_header in enumerate(pc.chunk_list):
            if not chunk_header:
                continue
            if chunk_header.addr == chunk_start_hex:
                table = [("index", "tid", "chunk_addr", "class_size")]
                table.append((index, pc.tid, chunk_header.addr, pc.class_size))
                print(assemble_table(table))
                FOUND = True
                break

    if not FOUND:
        logging.warning("from secondary used...")
        for use_block_item in scuheap.secondary.in_use_blocks_list:
            use_block = use_block_item.large_block
            if use_block.chunk_header.addr == chunk_start_hex:
                table = [("BlockAddr", "Prev", "Next",
                          "BlockEnd", "MapBase", "MapSize")]
                table.append((use_block.block_addr, use_block.l_prev,
                              use_block.l_next,
                              use_block.block_end,
                              use_block.map_base,
                              use_block.map_size))
                print(assemble_table(table))
                FOUND = True
                break

    if not FOUND:
        logging.warning("from secondary cached...")
        for cache_entry_item in scuheap.secondary.cache_entry_list:
            cache_entry = cache_entry_item.large_block
            if cache_entry.chunk_header.addr == chunk_start_hex:
                table = [("BlockAddr", "BlockEnd", "MapBase", "MapSize")]
                table.append((cache_entry.block_addr, cache_entry.block_end,
                              cache_entry.map_base, cache_entry.map_size))
                print(assemble_table(table))
                FOUND = True
                break

    if not FOUND:
        logging.warning("search in primary RegionInfo mapped user...")
        perclas_array_size = symbol_int_value('Allocator.Primary.NumClasses')
        class_id = -1
        address = int(chunk_start_hex, 16)
        for index in range(perclas_array_size):
            RegionBeg = int(scuheap.region_info_array[index].region_beg, 16)
            RegionEnd = int(scuheap.region_info_array[index].region_beg, 16) \
                - header_size + int(
                scuheap.region_info_array[index].allocated_user, 16)
            if address >= RegionBeg and address <= RegionEnd:
                class_id = index
                break

        if class_id != -1:
            index = class_id
            class_size = scuheap.perclass_array[index].class_size
            header_list = parse_allocated_chunks(class_size)
            for header_index, header in enumerate(header_list):
                if address == int(header.addr, 16):
                    table = [("index", "chunk_addr", "class_size")]
                    table.append((header_index, header.addr, class_size))
                    print(assemble_table(table))
                    FOUND = True
                    break

    if FOUND:
        header = parse_chunk_header(chunk_start_hex)
        logging.warning("dump chunk info {}".format(chunk_start_hex))

        if header:
            table = [("classid", "state", "origin", "user_addr",
                      "used_bytes", "offset", "check_sum")]
            table.append((header.class_id, header.state, header.origi,
                          header.user_addr, header.used_bytes,
                          header.offset, header.check_sum))
            print(assemble_table(table))
    else:
        logging.error("{} not a valid chunk".format(chunk_start_hex))


def print_timestamp():
    ts = time.time()
    st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    logging.warning('[parser] %s' % (st))


def dump_region_infos():
    global scuheap
    if not scuheap:
        logging.error("pls run scuparse first")
        return
    logging.error("RegionSize {}k".format(scuheap.region_size/1024))
    table = [("ClassId", "ClassSize", "RegionBeg",
              "AllocatedUser", "RegionSize")]
    for region_info in scuheap.region_info_array:
        table.append((region_info.class_id,
                      scuheap.perclass_array[region_info.class_id].class_size,
                      region_info.region_beg, region_info.allocated_user,
                      hex(scuheap.region_size)))

    print(assemble_table(table))


def dump_region_info(class_id):
    global scuheap
    if not scuheap:
        logging.error("pls run scuparse first")
        return
    table = [("ClassId", "ClassSize", "RegionBeg", "AllocatedUser")]
    region_info = scuheap.region_info_array[class_id]
    table.append((region_info.class_id,
                  scuheap.perclass_array[region_info.class_id].class_size,
                  region_info.region_beg, region_info.allocated_user))

    print(assemble_table(table))


def dump_all_chunks(class_size):
    print("dump_all_chunks ", class_size)
    header_list = parse_allocated_chunks(class_size)
    logging.warning("header_list size {}".format(len(header_list)))
    if header_list:
        table = [("index", "class_size", "addr", "user_addr", "state",
                  "origin", "used_bytes", "offset", "check_sum")]
        for i, header in enumerate(header_list):
            index = "  "
            if header.used_bytes > 0:
                index += "==>" + str(i)
            else:
                index += "   " + str(i)
            table.append((index, hex(class_size), header.addr,
                          header.user_addr, header.state, header.origi,
                          header.used_bytes, header.offset, header.check_sum))
        print(assemble_table(table))
        return
    logging.error("unmapped area class_size {}".format(class_size))


def parse_allocated_chunks(class_size):
    global scuheap
    if not scuheap:
        logging.error("pls run scuparse first")
        return

    class_id = -1
    header_list = []

    for i in range(len(scuheap.perclass_array)):
        if scuheap.perclass_array[i].class_size == class_size and i:
            class_id = i
            break

    if class_id == -1:
        logging.info("invailid class_size", class_size)
        return header_list

    logging.info("class_size {} class_id {}".format(class_size, class_id))

    if class_id != -1 and class_id:
        RegionBeg = int(scuheap.region_info_array[class_id].region_beg, 16)
        if scuheap.region_info_array[class_id].chunk_list:
            return scuheap.region_info_array[class_id].chunk_list
        AllocatedUser = int(
            scuheap.region_info_array[class_id].allocated_user, 16)
        logging.debug("RegionBeg {} AllocatedUser {} ".format(
            RegionBeg, AllocatedUser))
        if AllocatedUser and RegionBeg:
            addr = RegionBeg
            mem = read_bytes(RegionBeg, AllocatedUser)
            while addr < (RegionBeg + AllocatedUser):
                logging.info("RegionBeg {} AllocatedUser {} addr {}".format(
                    RegionBeg, AllocatedUser, addr))
                header_mem = mem[addr-RegionBeg:addr-RegionBeg+8]
                header = parse_chunk_header_mem(addr, header_mem)
                scuheap.user_addr_map[addr] = header
                addr = addr + class_size
                header_list.append(header)
            scuheap.region_info_array[class_id].fill_chunk_list(header_list)
        else:
            logging.debug('{} is invalid'.format(class_size))
            pass
    return header_list


def parse_region_infos(scuheap):
    perclas_array_size = symbol_int_value('Allocator.Primary.NumClasses')
    region_size = symbol_int_value('Allocator.Primary.RegionSize')
    scuheap.set_region_size(region_size)

    region_infos = []
    if arch_dword_size() == 8:
        region_info_str = 'Allocator.Primary.RegionInfoArray'
        for i in range(perclas_array_size):
            RegionBeg = hex(symbol_int_value(
                '{}[{}].RegionBeg'.format(region_info_str, i)))
            AllocatedUser = hex(symbol_int_value(
                '{}[{}].AllocatedUser'.format(region_info_str, i)))
            # if AllocatedUser != '0x0':
            region_info = RegionInfo(
                i, None, 0, RegionBeg, AllocatedUser, None, None, None)
            region_infos.append(region_info)

    else:
        region_info_str = 'Allocator.Primary.SizeClassInfoArray'
        for i in range(perclas_array_size):
            RegionBeg = hex(symbol_int_value(
                '{}[{}].CurrentRegion'.format(region_info_str, i)))
            AllocatedUser = hex(symbol_int_value(
                '{}[{}].CurrentRegionAllocated'.format(region_info_str, i)))

            # if AllocatedUser != '0x0':
            region_info = RegionInfo(
                i, None, 0, RegionBeg, AllocatedUser, None, None, None)
            region_infos.append(region_info)

    scuheap.fill_region_info(region_infos)


def parse_general_perclass(scuheap):
    perclas_array_size = symbol_int_value('Allocator.Primary.NumClasses')
    scuheap.set_num_classes(perclas_array_size)
    logging.info("info array_size {}".format(perclas_array_size))
    thread_size = 8
    tsd_info = []
    # symbol dump

    for ti in range(thread_size):
        tsd_str = '&Allocator.TSDRegistry.TSDs[{}]'.format(ti)
        tsd_addr = str(gdb.parse_and_eval(tsd_str)).split()[0]
        tsd_info.append(tsd_addr)

        for i in range(perclas_array_size):
            perclass_str = 'Allocator.TSDRegistry.TSDs[{}]. \
                Cache.PerClassArray[{}]'.format(ti, i)
            count = symbol_int_value('{}.Count'.format(perclass_str))
            max_count = symbol_int_value('{}.MaxCount'.format(perclass_str))
            class_size = symbol_int_value('{}.ClassSize'.format(perclass_str))
            chunk_str = '{}.Chunks'.format(perclass_str)
            chunk_list = []
            chunk_valid = False
            for ci in range(max_count):
                chunk_addr = str(gdb.parse_and_eval(
                    '{}[{}]'.format(chunk_str, ci))).split()[0]
                if chunk_addr != '0x0':
                    chunk_header = parse_chunk_header(chunk_addr)
                    chunk_list.append(chunk_header)
                else:
                    chunk_list.append(None)
                perclass = PerClass(i, ti, count, max_count,
                                    class_size, chunk_list)
            if max_count:
                scuheap.fill_perclass(perclass)
    scuheap.set_tsd_info(tsd_info)


def dump_secondary():
    global scuheap
    if not scuheap:
        logging.error("pls run scuparse first")
        return
    if scuheap.secondary:
        table = [("AllocatedBytes", "FreedBytes", "LargestSize",
                  "NumberOfAllocs", "NumberOfFrees",
                  "MaxEntriesCount", "MaxEntrySize")]
        table.append((scuheap.secondary.allocated_bytes,
                      scuheap.secondary.free_bytes,
                      scuheap.secondary.largest_size,
                      scuheap.secondary.number_of_allocs,
                      scuheap.secondary.number_of_frees,
                      scuheap.secondary.max_entries_count,
                      scuheap.secondary.max_entry_size))
        logging.info("dump secondary:")
        print(assemble_table(table))
        table_cache = [("BlockAddr", "ChunkHeaderAddr", "UserAddr",
                        "BlockEnd", "MapBase", "MapSize",
                        "State", "Origi", "UsedBytes")]
        for cache_entry_item in scuheap.secondary.cache_entry_list:
            cache_entry = cache_entry_item.large_block
            table_cache.append((cache_entry.block_addr,
                                cache_entry.chunk_header_addr,
                                cache_entry.user_start_addr,
                                cache_entry.block_end,
                                cache_entry.map_base,
                                cache_entry.map_size,
                                cache_entry.chunk_header.state,
                                cache_entry.chunk_header.origi,
                                cache_entry.chunk_header.used_bytes))

        logging.error("dump secondary cache Frees:")
        print(assemble_table(table_cache))
        in_use_table = [("BlockAddr", "ChunkHeaderAddr", "UserAddr",
                         "Prev", "Next", "BlockEnd", "MapBase",
                         "MapSize", "State", "Origi", "UsedBytes")]

        for in_use_block_item in scuheap.secondary.in_use_blocks_list:
            in_use_block = in_use_block_item.large_block
            in_use_table.append((in_use_block.block_addr,
                                 in_use_block.chunk_header_addr,
                                 in_use_block.user_start_addr,
                                 in_use_block_item.l_prev,
                                 in_use_block_item.l_next,
                                 in_use_block.block_end,
                                 in_use_block.map_base,
                                 in_use_block.map_size,
                                 in_use_block.chunk_header.state,
                                 in_use_block.chunk_header.origi,
                                 in_use_block.chunk_header.used_bytes))
        logging.error("dump secondary inuse block:")
        print(assemble_table(in_use_table))


def parse_cache_entry():
    secondary_str = 'Allocator.Secondary'
    CacheEntiesSize = symbol_int_value(
        '{}.{}'.format(secondary_str, "Cache.EntriesCount"))
    cache_str = '{}.{}'.format(secondary_str, "Cache")
    cache_entry_list = []
    for i in range(CacheEntiesSize):
        CacheEntryBlock = symbol_int_value(
            '{}.Entries[{}].Block'.format(cache_str, i))
        CacheBlockEnd = symbol_int_value(
            '{}.Entries[{}].BlockEnd'.format(cache_str, i))
        CacheMapBase = symbol_int_value(
            '{}.Entries[{}].MapBase'.format(cache_str, i))
        CacheMapSize = symbol_int_value(
            '{}.Entries[{}].MapSize'.format(cache_str, i))
        cache_entry = SecondaryCacheEntry(hex(CacheEntryBlock), hex(
            CacheBlockEnd), hex(CacheMapBase), hex(CacheMapSize))
        cache_entry_list.append(cache_entry)
        scuheap.user_addr_map[int(
            cache_entry.large_block.user_start_addr, 16)] = cache_entry
    return cache_entry_list


def parse_secondary_in_used_blocks():
    secondary_str = 'Allocator.Secondary'
    first = hex(symbol_int_value('{}.InUseBlocks.First'.format(secondary_str)))
    last = hex(symbol_int_value('{}.InUseBlocks.Last'.format(secondary_str)))
    in_use_blocks_list = []
    if first == '0x0':
        return in_use_blocks_list
    header = parse_large_header(first)
    if header.large_block.block_end is not '0x0':
        scuheap.user_addr_map[int(
            header.large_block.user_start_addr, 16)] = header
        in_use_blocks_list.append(header)
    while int(header.l_next, 16):
        logging.debug("header_next", header.l_next)
        header = parse_large_header(header.l_next)
        scuheap.user_addr_map[int(
            header.large_block.user_start_addr, 16)] = header
        in_use_blocks_list.append(header)
    return in_use_blocks_list


def parse_large_header(header_addr):
    dword_size = arch_dword_size()
    logging.info("parse_large_header word_size: {}".format(dword_size))
    l_prev = read_addr_bytes_hex(header_addr, dword_size)
    l_next = read_addr_bytes_hex(hexadd(header_addr, dword_size), dword_size)
    block_end = read_addr_bytes_hex(
        hexadd(header_addr, dword_size*2), dword_size)
    map_base = read_addr_bytes_hex(
        hexadd(header_addr, dword_size*3), dword_size)
    map_size = read_addr_bytes_hex(
        hexadd(header_addr, dword_size*4), dword_size)
    return SecondaryInUseBlocksPtr(header_addr, l_prev, l_next,
                                   block_end, map_base, map_size)


def parse_secondary(scuheap):
    secondary_str = 'Allocator.Secondary'
    AllocatedBytes = '{}.{}'.format(secondary_str, "AllocatedBytes")
    FreedBytes = '{}.{}'.format(secondary_str, "FreedBytes")
    LargestSize = '{}.{}'.format(secondary_str, "LargestSize")
    NumberOfAllocs = '{}.{}'.format(secondary_str, "NumberOfAllocs")
    NumberOfFrees = '{}.{}'.format(secondary_str, "NumberOfFrees")
    MaxEntrySize = '{}.{}'.format(
        secondary_str, "Cache.MaxEntrySize.ValDoNotUse")
    MaxEntiesCount = '{}.{}'.format(
        secondary_str, "Cache.MaxEntriesCount.ValDoNotUse")
    cache_entry_list = parse_cache_entry()
    in_use_blocks_list = parse_secondary_in_used_blocks()

    secondary = Secondary(cache_entry_list, in_use_blocks_list,
                          symbol_int_value(AllocatedBytes),
                          symbol_int_value(FreedBytes),
                          symbol_int_value(LargestSize),
                          symbol_int_value(NumberOfAllocs),
                          symbol_int_value(NumberOfFrees),
                          symbol_int_value(MaxEntrySize),
                          symbol_int_value(MaxEntiesCount))
    scuheap.fill_secondary(secondary)


def read_addr_byte(addr):
    return read_addr_bytes(addr, 1)


def read_addr_half_byte_l(addr):
    symbol_addr_byte_hex = read_addr_bytes(addr, 1)
    return symbol_addr_byte_hex[1]


def read_addr_half_byte_h(addr):
    symbol_addr_byte_hex = read_addr_bytes(addr, 1)
    return symbol_addr_byte_hex[0]


def read_addr_bytes_hex(addr, size):
    symbol_addr_byte_hex = read_addr_bytes(addr, size)
    return hex(int(symbol_addr_byte_hex, 16))


def read_addr_bytes(addr, size):
    symbol_addr_var_str = None
    raw_out = gdb.execute('x/{}xb {}'.format(size, addr), to_string=True)
    for line in raw_out.split('\n'):
        if not line:
            continue
        one_line = line.split('\t')
        symbol_addr_byte_hex = "".join(
            [i.replace('0x', '') for i in one_line[-1:0:-1]])

    return symbol_addr_byte_hex


def read_proc_mappings():
    raw_out = gdb.execute('i proc mappings', to_string=True)
    gdb_elf.parse_elf(raw_out)


def parse_symbol(addr):
    try:
        gdb_out = gdb.execute('x {}'.format(addr), to_string=True)
        line_list = gdb_out.split()
        if line_list[1].startswith('<'):
            symbol = line_list[1].lstrip('<').rstrip('>:')
            ln = symbol.find('+')
            lino = 0
            if ln != -1:
                sym = symbol[:ln]
                lino = symbol[ln+1:]
            cmd = ['c++filt', sym]
            return gdb_elf.RunAndCheckOutput(cmd, verbose=False) \
                .rstrip("\n").strip()
    except Exception as e:
        return None


def hexadd(addr, offset):
    return hex(int(addr, 16) + offset)


def parse_chunk_header_from_list(raw_out, addr, use_size=None):
    class_id = int(utils.read_addr_byte(raw_out, 0), 16)
    state_origi = int(utils.read_addr_half_byte_l(raw_out, 1), 16)
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

    size_or_unused_bytes_low = utils.read_addr_half_byte_h(raw_out, 1)
    size_or_unused_bytes_high = utils.read_addr_bytes(raw_out, 2, 2)
    size_or_unused_bytes = int(
        size_or_unused_bytes_low, 16) + int(size_or_unused_bytes_high, 16)*16
    if use_size:
        used_bytes = use_size - size_or_unused_bytes
    else:
        used_bytes = size_or_unused_bytes

    offset = utils.read_addr_bytes_hex(raw_out, 4, 2)
    check_sum = utils.read_addr_bytes_hex(raw_out, 6, 2)

    return ChunkHeader(class_id, addr, state, origi,
                       used_bytes, offset, check_sum)


def parse_chunk_header_mem(addr, header_mem, use_size=None):
    raw_out = [hex(i)[2:] if len(hex(i)) > 3 else "0"+hex(i)[2:]
               for i in list(header_mem)]
    return parse_chunk_header_from_list(raw_out, hex(addr), use_size)


def parse_chunk_header(addr, use_size=None):
    raw_out = gdb.execute('x/8xb {}'.format(addr), to_string=True)
    raw_out = [bt[2:] for bt in raw_out.split(":")[1].strip().split()]
    raw_zero_padding = ['00', '00', '00', '00', '00', '00', '00', '00']
    if len(raw_out) < 8:
        raw_out = raw_zero_padding

    return parse_chunk_header_from_list(raw_out, addr, use_size)


def dump_classid(classid):
    global scuheap
    if not scuheap:
        logging.error("pls run scuparse first")
        return
    if classid >= 0 and classid <= scuheap.num_classes:
        logging.error("class_size {}".format(
            scuheap.perclass_array[classid].class_size))
    else:
        logging.error("invalid classid {}".format(classid))


def dump_hit_stat(sub_arg=None):
    global d_used_hit_list
    logging.error(
        "========================== hit statistics =========================")
    for it in d_used_hit_list:
        logging.error("{} hit {}".format(it[0], len(it[1])))
        if sub_arg == "d":
            table = [("class_id", "state", "origi",
                      "size_or_used_bytes", "addr",
                      "user_addr_start", "check_sum",
                      "symbol_addr", "symbol_info")]
            for header in it[1]:
                table.append((header.class_id, header.state, header.origi,
                              header.used_bytes, header.addr, header.user_addr,
                              header.check_sum, header.symbol_addr,
                              header.symbol_info))
            print(assemble_table(table))
        else:
            for header in it[1]:
                print("{}".format(header.user_addr), end=' ')
            print()


def dump_size_stat(sub_arg=None):
    global d_used_size_list
    logging.error(
        "===================== total used bytes statis===================")
    for it in d_used_size_list:
        logging.error("{} total used_bytes {}".format(
            it[0], it[1][0].used_bytes * len(it[1])))
        if sub_arg == "d":
            table = [("class_id", "state", "origi",
                      "size_or_used_bytes", "addr",
                      "user_addr_start", "check_sum",
                      "symbol_addr", "symbol_info")]
            for header in it[1]:
                table.append((header.class_id, header.state,
                              header.origi, header.used_bytes,
                              header.addr, header.user_addr,
                              header.check_sum, header.symbol_addr,
                              header.symbol_info))
            print(assemble_table(table))
        else:
            for header in it[1]:
                print("{}".format(header.user_addr), end='  ')
            print()


def dump_all_chunk_hit_stat(arg):
    global d_used
    collect_all_chunk_header()
    if arg:
        cmd_list = arg.split()
        sub_arg = cmd_list[1] if len(cmd_list) == 2 else None
        if cmd_list[0] == "h":
            dump_hit_stat(sub_arg)
        elif cmd_list[0] == "s":
            dump_size_stat(sub_arg)
    else:
        dump_hit_stat()
        dump_size_stat()


def collect_all_chunk_header():
    global scuheap
    global d_used, d_used_size_list, d_used_hit_list
    if not scuheap:
        logging.error("pls run scuparse first")
        return
    print_timestamp()
    if d_used:
        return
    d_used = defaultdict(list)
    logging.warning("secondary used...")
    for use_block_item in scuheap.secondary.in_use_blocks_list:
        use_block = use_block_item.large_block
        table = [("Prev", "Next", "BlockEnd", "MapBase",
                  "MapSize", "state", "origi",
                  "used_bytes", "user_addr_start",
                  "check_sum", "symbol_addr", "symbol_info")]
        table.append((use_block_item.l_prev,
                      use_block_item.l_next,
                      use_block.block_end,
                      use_block.map_base,
                      use_block.map_size,
                      use_block.chunk_header.state,
                      use_block.chunk_header.origi,
                      use_block.chunk_header.used_bytes,
                      use_block.chunk_header.user_addr,
                      use_block.chunk_header.check_sum,
                      use_block.chunk_header.symbol_addr,
                      use_block.chunk_header.symbol_info))
        # print(assemble_table(table))
        if use_block.chunk_header.state == "Allocated" or \
                use_block.chunk_header.state == "Quarantined":
            if use_block.chunk_header.symbol_info:
                d_used[use_block.chunk_header.symbol_info].append(
                    use_block.chunk_header)

    logging.warning("secondary cache...")
    for cache_entry_item in scuheap.secondary.cache_entry_list:
        cache_entry = cache_entry_item.large_block
        table = [("BlockAddr", "BlockEnd", "MapBase", "MapSize",
                  "state", "origi",
                  "used_bytes", "user_addr_start",
                  "check_sum", "symbol_addr", "symbol_info")]
        table.append((cache_entry.block_addr, cache_entry.block_end,
                      cache_entry.map_base,
                      cache_entry.map_size,
                      cache_entry.chunk_header.state,
                      cache_entry.chunk_header.origi,
                      cache_entry.chunk_header.used_bytes,
                      cache_entry.chunk_header.user_addr,
                      cache_entry.chunk_header.check_sum,
                      cache_entry.chunk_header.symbol_addr,
                      cache_entry.chunk_header.symbol_info))
        # print(assemble_table(table))
        if cache_entry.chunk_header.state == "Allocated" or \
                cache_entry.chunk_header.state == "Quarantined":
            if cache_entry.chunk_header.symbol_info:
                d_used[cache_entry.chunk_header.symbol_info].append(
                    cache_entry.chunk_header)

    logging.warning("primary RegionInfo mapped user...")
    perclas_array_size = symbol_int_value('Allocator.Primary.NumClasses')
    for index in range(1, perclas_array_size):
        class_size = scuheap.perclass_array[index].class_size
        header_list = parse_allocated_chunks(class_size)
        for header_index, header in enumerate(header_list):
            table = [("index", "chunk_addr", "class_size",
                      "class_id", "state", "origi",
                      "used_bytes", "user_addr_start",
                      "check_sum", "symbol_addr", "symbol_info")]
            table.append((header_index, header.addr, class_size,
                          header.class_id, header.state, header.origi,
                          header.used_bytes,
                          header.user_addr,
                          header.check_sum,
                          header.symbol_addr,
                          header.symbol_info))
            # print(assemble_table(table))
            if header.state == "Allocated" or header.state == "Quarantined":
                if header.symbol_info:
                    d_used[header.symbol_info].append(header)

    print_timestamp()
    d_used_hit_list = sorted(d_used.items(), lambda x,
                             y: cmp(len(x[1]), len(y[1])), reverse=True)
    d_used_size_list = sorted(d_used.items(),
                              lambda x, y:
                              cmp(len(x[1]) * x[1][0].used_bytes,
                                  len(y[1]) * y[1][0].used_bytes),
                              reverse=True)


def parse_tls(scuheap):
    elm_addr = convert2int(get_value("g_thread_list"))
    if elm_addr == 0:
        elm_addr = bss_search.get_g_thread_list()
    tid_infos = {}
    word_size = arch_dword_size()
    pthread_internal_size = type_size("pthread_internal_t")
    tid_infos = []
    while elm_addr != 0:
        elm_mem = read_bytes(elm_addr, pthread_internal_size)
        elm_tid = read_struct_member_value(elm_mem,
                                           "pthread_internal_t",
                                           "tid", 4)
        logging.debug("elm_tid: {}".format(elm_tid))
        elm_addr = read_struct_member_value(elm_mem,
                                            "pthread_internal_t",
                                            "next", arch_dword_size())
        bionic_tls_addr = read_struct_member_value(elm_mem,
                                                   "pthread_internal_t",
                                                   "bionic_tls",
                                                   arch_dword_size())
        logging.debug("bionic_tls_addr {}".format(hex(bionic_tls_addr)))
        # 64 bit and 32 bit
        bionic_tcb_addr = bionic_tls_addr - 9 * word_size  # raw_slots_storage
        bionic_santizer_addr = bionic_tcb_addr + \
            7 * word_size  # tpidr_el0[SANTIZER_SLOT]
        tsd_address = hex(read_word(bionic_santizer_addr))
        tsd_ind = None
        for index, tsd_addr in enumerate(scuheap.tsdinfo):
            if tsd_addr == tsd_address:
                tsd_ind = index
                break
        tid_infos.append(TidInfo(elm_tid, tsd_addr, tsd_ind))
    scuheap.set_tid_infos(tid_infos)

# parse functions


def parse():
    global d_used, d_used_size_list, d_used_hit_list
    d_used = None
    try:
        global scuheap
        logging.warning('[parser] parsing structures from memory...')
        print_timestamp()
    except Exception as e:
        traceback.print_exc()

    scuheap = ScuMalloc()
    parse_general_perclass(scuheap)
    parse_secondary(scuheap)
    parse_region_infos(scuheap)
    parse_tls(scuheap)
    logging.warning('[parser] structures parsed')
    print_timestamp()


if __name__ == '__main__':
    main()
