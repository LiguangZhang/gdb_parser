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

import scudo_parser
import gdb_common

HeaderSize = 16


class ScuMalloc:
    def __init__(self, path=None):
        self.perclass_array = list()
        self.perclass_array_size = None
        self.secondary = None
        self.region_size = None
        self.region_info_array = list()
        self.chunk_header_size = HeaderSize
        self.tsdinfo = None

        if(gdb_common.arch_dword_size() == 8):
            self.pointer_len = 8
        else:
            self.pointer_len = 4
        self.user_addr_map = {}

    def fill_perclass(self, perclass):
        self.perclass_array.append(perclass)

    def fill_secondary(self, secondary):
        self.secondary = secondary

    def fill_region_info(self, region_infos):
        self.region_info_array = region_infos

    def set_num_classes(self, num_classes):
        self.num_classes = num_classes

    def set_region_size(self, region_size):
        self.region_size = region_size

    def set_tsd_info(self, tsd_info):
        self.tsdinfo = tsd_info

    def set_tid_infos(self, tid_infos):
        self.tid_infos = tid_infos


class PerClass:
    def __init__(self, class_id, tid, count, max_count,
                 class_size, chunk_list):
        self.class_id = class_id
        self.tid = tid
        self.count = count
        self.max_count = max_count
        self.class_size = class_size
        self.chunk_list = chunk_list


class LargeBlock:
    def __init__(self, BlockAddr, BlockEnd, MapBase, MapSize):
        self.block_addr = BlockAddr
        dword_size = gdb_common.arch_dword_size()
        if dword_size == 8:
            self.chunk_header_addr = hex(int(BlockAddr, 16) + 48)
            self.user_start_addr = hex(int(BlockAddr, 16) + 64)
        else:
            self.chunk_header_addr = hex(int(BlockAddr, 16) + 32)
            self.user_start_addr = hex(int(BlockAddr, 16) + 48)
        self.block_end = BlockEnd
        self.map_base = MapBase
        self.map_size = MapSize
        self.use_size = int(self.block_end, 16) - int(self.user_start_addr, 16)
        self.chunk_header = scudo_parser.parse_chunk_header(
            self.chunk_header_addr, self.use_size)


class SecondaryCacheEntry:
    def __init__(self, BlockAddr, BlockEnd, MapBase, MapSize):
        self.large_block = LargeBlock(BlockAddr, BlockEnd, MapBase, MapSize)


class SecondaryInUseBlocksPtr:
    def __init__(self, BlockAddr, Prev, Next, BlockEnd, MapBase, MapSize):
        self.block_addr = BlockAddr
        self.l_prev = Prev
        self.l_next = Next
        self.large_block = LargeBlock(BlockAddr, BlockEnd, MapBase, MapSize)


class Secondary:
    def __init__(self, CacheEntryList, InUseBlocksList,
                 AllocatedBytes, FreedBytes, LargestSize,
                 NumberOfAllocs, NumberOfFrees, MaxEntrySize, MaxEntiesCount):
        self.cache_entry_list = CacheEntryList
        self.in_use_blocks_list = InUseBlocksList
        self.allocated_bytes = AllocatedBytes
        self.free_bytes = FreedBytes
        self.largest_size = LargestSize
        self.number_of_allocs = NumberOfAllocs
        self.number_of_frees = NumberOfFrees
        self.max_entry_size = MaxEntrySize
        self.max_entries_count = MaxEntiesCount


class Chunk:
    def __init__(self, chunk_header, addr):
        self.chunk_header = chunk_header
        self.addr = addr


class ChunkHeader:
    def __init__(self, classid, addr, state, origi,
                 used_bytes, offset, check_sum):
        self.class_id = classid
        self.addr = addr
        self.user_addr = hex(int(addr, 16)+16)
        self.state = state
        self.origi = origi
        self.used_bytes = used_bytes
        self.offset = offset
        self.check_sum = check_sum
        self.symbol_addr = None
        self.symbol_info = None

        if self.state == "Allocated" or self.state == "Quarantined":
            dword_size = gdb_common.arch_dword_size()
            self.symbol_addr = scudo_parser.read_addr_bytes_hex(
                self.user_addr, dword_size)
            self.symbol_info = scudo_parser.parse_symbol(self.symbol_addr)


class ChunkHeaderT:
    def __init__(self):
        self.ClassId = 8
        self.state = 2
        self.orign = 2
        self.size_or_unusedbytes = 20
        self.offset = 16
        self.checksum = 16


class RegionInfo:
    def __init__(self, ClassId, FreeList, CanRelease, RegionBeg, AllocatedUser,
                 ReleaseInfo, Stats, Chunk_List):
        self.class_id = ClassId
        self.free_list = FreeList
        self.can_release = CanRelease
        self.region_beg = RegionBeg
        self.allocated_user = AllocatedUser
        self.release_info = ReleaseInfo
        self.stats = Stats
        self.chunk_list = Chunk_List

    def fill_chunk_list(self, ChunkList):
        self.chunk_list = ChunkList


class TidInfo:
    def __init__(self, tid, tsd_addr, tsd_ind):
        self.tid = tid
        self.tsd_addr = tsd_addr
        self.tsd_ind = tsd_ind
