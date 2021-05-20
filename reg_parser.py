import gdb
import gdb_common
import reg_class
import utils
from reg_parse_cfg import *

def help():
    print("help")

def version():
    print("version")

def parse_update(name):
    gdb_common.clear_cache()
    for u in reg_info.unit_list:
        if name is None:
            val = gdb_common.read_addr_width(u.addr, int(u.offset)%32, int(u.width))
            u.update(int(val,2))
        else:
            if(u.ip_name == name):
                val = gdb_common.read_addr_width(u.addr, int(u.offset)%32, int(u.width))
                u.update(int(val,2))

def dump_info(ip_name, g_name, tofile):
    parse_update(ip_name)
    last_gname = None
    last_ip_name = None
    table = [("name", "addr", "offset", "value", "group_name", "group_offset")]
    if ip_name is not None:
        for u in reg_info.unit_list:
            if(u.ip_name == ip_name):
                if(g_name is not None and (u.g_name == g_name)):
                    table.append((u.reg_name, hex(u.addr), u.off_str, u.d_val, u.g_name, 
                            reg_info.group_dict[u.g_name].offset))
                elif(g_name is None):
                    if(u.g_name != last_gname and last_gname is not None):
                        table.append(('--', None, None, None, None, None))
                    table.append((u.reg_name, hex(u.addr), u.off_str, u.d_val, u.g_name, 
                            reg_info.group_dict[u.g_name].offset))
                    last_gname = u.g_name
    else:
        print("u list size", len(reg_info.unit_list))
        for u in reg_info.unit_list:
            if(u.g_name != last_gname and last_gname is not None):
                table.append(('--', None, None, None, None, None))
            if(u.ip_name != last_ip_name):
                table.append(('==', u.ip_name, None, None, None, None))
                table.append(('--', None, None, None, None, None))
            table.append((u.reg_name, hex(u.addr), u.off_str, u.d_val, u.g_name, 
                    reg_info.group_dict[u.g_name].offset))
            last_gname = u.g_name
            last_ip_name = u.ip_name
    output = utils.assemble_table(table)
    print(output)
    if(tofile):
        with open(tofile, "w") as f:
            f.write(output)

def dump_ip(arg):
    arg_list = arg.split(" ")
    g_name = None
    if(len(arg_list) > 1):
        g_name = arg_list[1]
    ip_name = arg_list[0]
    dump_info(ip_name, g_name, None)

def dump_ip_all():
    tofile = "/home/liguang/gdb_temp.log"
    dump_info(None, None, tofile)