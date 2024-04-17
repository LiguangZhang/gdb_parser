#!/usr/bin/env python2
# -*- coding:utf-8 -*-
from capstone import *
from capstone.mips import *
from gdb_common import *
import sys
import subprocess
import os

# TARGET_ELF_FILE = "/home/liguang/work_space/siflower/freertos/FreeRTOS-MIPS/FreeRTOS/Demo/MIPS32_GCC/RTOSDemo.elf"
TARGET_ELF_FILE = "/home/liguang/work_space/benji/splfdl_evb/objs_spl/SPL.elf"
TARGET_ELF_FILE_PATH = os.path.dirname(TARGET_ELF_FILE)
addr2line = "mips-mti-elf-addr2line"
addr2line_cmd_src = [addr2line, "-e", TARGET_ELF_FILE, "-a"]

class ExternalError(RuntimeError):
      pass

def Run(args, verbose=None, **kwargs):
  if 'stdout' not in kwargs and 'stderr' not in kwargs:
    kwargs['stdout'] = subprocess.PIPE
    kwargs['stderr'] = subprocess.STDOUT
  # Don't log any if caller explicitly says so.
  if verbose != False:
    print("  Running: ", " ".join(args))
  return subprocess.Popen(args, **kwargs)

def RunAndCheckOutput(args, verbose=None, **kwargs):
  proc = Run(args, verbose=verbose, **kwargs)
  output, _ = proc.communicate()
  # Don't log any if caller explicitly says so.
  if verbose != False and output:
    print(output.decode('utf-8'))
  if proc.returncode != 0:
    raise ExternalError(
        "Failed to run command '{}' (exit code {}):\n{}".format(
            args, proc.returncode, output))
  return output

class mips_frame_info:
    def __init__(self, ip, ra, frame_size, func_name):
        self.ip = ip
        self.ra = ra
        self.frame_size = frame_size
        self.func_name = func_name

def is_jal_jalr_jr_ins(insn):
    if(insn.mnemonic == "jal") or (insn.mnemonic == "jr"):
        return True
    return False

def is_sp_move_ins(insn):
    if(insn.op_str.startswith("$sp, $sp")):
        if(insn.mnemonic == "addiu"):
            return True
    return False

def is_ra_save_ins(insn):
    if(insn.mnemonic == "sw"):
        if(insn.op_str.startswith("$ra")) and (insn.op_str.endswith("($sp)") or insn.op_str.endswith("($fp)")):
            return True
    return False

def padding(x):
    if(len(x)%8==0):
        return x
    res = "0"*((len(x)/8+1)*8-len(x))+x
    return res

arch = CS_ARCH_MIPS
mode = CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN
md = Cs(arch, mode)
md.detail = True

def parse_symbol(addr):
    try:
        gdb_out = gdb.execute('x {}'.format(addr), to_string=True)
        # print(gdb_out)
        line_list = gdb_out.split()
        if line_list[1].startswith('<'):
            symbol = line_list[1].lstrip('<').rstrip('>:')
            ln = symbol.find('+')
            lino = 0
            if ln != -1:
                sym = symbol[:ln]
                lino = symbol[ln+1:]
            else:
                sym = symbol
            return(sym, lino)
    except Exception as e:
        return None

def parse_ip(ip):
    addr2line_cmd = []
    addr2line_cmd.extend(addr2line_cmd_src)
    addr2line_cmd.append(ip)
    symbol_info = RunAndCheckOutput(addr2line_cmd, False).rstrip("\n").split("\n")[-1]
    pos = symbol_info.find(TARGET_ELF_FILE_PATH)
    if pos != -1:
        symbol_info = symbol_info[len(TARGET_ELF_FILE_PATH):].lstrip("/")
    return symbol_info

def dump_caller(sp, epc, first_ra):
    mips_frame_info_stack = []
    ra = epc
    sp_depth = 0
    while len(mips_frame_info_stack)<20 and sp_depth < 10:
        try:
            # print(ra, len(mips_frame_info_stack))
            (symbol, lino) = parse_symbol(ra)
            # print(symbol, lino)
            ip = ra - int(lino)
            mem = read_bytes(ip, 20*4)
            ra_sp_offset = 0
            frame_size = 0
            for i in range(0, 80, 4):
                for insn in md.disasm(mem[i:i+4], ip):
                    insn_str = ("0x%x:\t%s\t%s\n" % (insn.address, insn.mnemonic, insn.op_str))
                    # print(insn_str)
                    if(is_ra_save_ins(insn)):
                        ra_sp_offset = insn.op_str.split(',')[-1].split('(')[0]
                        break
                    if(is_sp_move_ins(insn) and frame_size == 0):
                        frame_size = insn.op_str.split(",")[-1]
                        # print("frame_size:", frame_size)
            # print("ra_sp_offset: {}, frame_size {}, len(mips_frame_info_stack) {}".format(ra_sp_offset, frame_size, len(mips_frame_info_stack)))
            if ra_sp_offset == 0 and frame_size != 0 and len(mips_frame_info_stack) == 0:
                mp = mips_frame_info(ip, ra, frame_size, symbol)
                mips_frame_info_stack.append(mp)
                sp = sp - int(frame_size, 16)
                ra = first_ra
                continue
            elif ra_sp_offset == 0 and frame_size == 0 and len(mips_frame_info_stack) == 0:
                mp = mips_frame_info(ip, ra, frame_size, symbol)
                mips_frame_info_stack.append(mp)
                ra = first_ra
                continue
            elif ra_sp_offset == 0 and frame_size != 0 and len(mips_frame_info_stack) == 1:
                sp = sp - int(frame_size, 16)
                sp_depth = sp_depth + 1
                continue
            else:
                mp = mips_frame_info(ip, ra, frame_size, symbol)
                mips_frame_info_stack.append(mp)
            # print("1111", hex(sp + int(ra_sp_offset, 16)))
            ra = read_word(sp + int(ra_sp_offset, 16))
            # print("ra:", hex(ra))
            sp = sp - int(frame_size, 16)
            # print("sp:", hex(sp))
        except Exception as e:
            break
    out = ""
    for mp in mips_frame_info_stack:
        out += "{} in {} +{}  {}\n".format(hex(mp.ra), mp.func_name, mp.ra-mp.ip, parse_ip(hex(mp.ra)))
    return out

def test():
    epc = 0xa020a7f8
    (symbol, lino) = parse_symbol(0xa020a790)
    print(symbol, lino)
    mem = read_bytes(epc, 100*4);
    for i in range(0, 400, 4):
        for insn in md.disasm(mem[i:i+4], 0xa0000000):
            insn_str = ("0x%x:\t%s\t%s\n" % (insn.address, insn.mnemonic, insn.op_str))
            print(insn_str)
    

if __name__ == '__main__':
    arch = CS_ARCH_MIPS
    mode = CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN
    md = Cs(arch, mode)
    md.detail = True
    print("pass")
    symlist = ['0x27bdffe0', '0xafbf001c', '0x0c082966']
    for insn in md.disasm(padding((symlist[2]).lstrip('0x')).decode("hex"), 2):
        print("11")
        insn_str = ("0x%x:\t%s\t%s\n" % (insn.address, insn.mnemonic, insn.op_str))
        print(insn_str)
        if(is_jal_jalr_jr_ins(insn)):
            print("1")
        if(is_sp_move_ins(insn)):
            print("2")
        if(is_ra_save_ins(insn)):
            print("3")
        
    