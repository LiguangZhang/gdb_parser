import reg_class
import re

ip_dict = {}
group_dict = {}
unit_list = []
reg_info = reg_class.REG(ip_dict, group_dict, unit_list)
IP_NAME = ""
GROUP_NAME = ""
global_path = "/home/liguang/work_space/register_parser/"

def parse_ip(u_list):
    global IP_NAME
    IP_NAME = u_list[1]
    ip = reg_class.IP(IP_NAME, u_list[2])
    reg_info.fill_ip(ip)

def parse_group(u_list):
    global IP_NAME, GROUP_NAME
    GROUP_NAME = u_list[1].lower()
    addr = int(reg_info.ip_dict[IP_NAME].base_addr, 16) + int(u_list[2], 16)
    group = reg_class.GROUP(GROUP_NAME, u_list[2], IP_NAME, addr)
    reg_info.fill_group(group)

def parse_group_ext(u_list):
    global IP_NAME, GROUP_NAME
    GROUP_NAME = u_list[1].lower()
    #print(u_list[2])
    g_offset = eval(u_list[2])
    g_addr = g_offset + int(reg_info.ip_dict[IP_NAME].base_addr, 16)
    group = reg_class.GROUP(GROUP_NAME, hex(g_offset), IP_NAME, g_addr)
    reg_info.fill_group(group)
    for u in reg_info.unit_list:
        if(u.g_name.startswith(GROUP_NAME[:len(GROUP_NAME)-1]) and u.g_name[-1] == '0'):
            addr = g_addr
            if int(u.offset) >= 32:
                addr += 4
            ext_unit = reg_class.UNIT_INFO(u.reg_name, u.offset, 
                u.width, u.unit, GROUP_NAME, u.ip_name, addr)
            reg_info.fill_unit(ext_unit)

def parse_base_unit(u_list):
    global IP_NAME, GROUP_NAME
    addr = int(reg_info.ip_dict[IP_NAME].base_addr, 16) \
            +  int(reg_info.group_dict[GROUP_NAME].offset, 16)
    if(int(u_list[1]) >= 32):
        addr += 4
    base_unit = reg_class.UNIT_INFO(u_list[0].lower(), u_list[1], u_list[2], u_list[3], GROUP_NAME, IP_NAME, addr)
    #print("unit addr", addr)
    reg_info.fill_unit(base_unit)

def parse_line(line):
    if line.startswith("#"):
        return
    u_list = re.split(r"[ ]+", line)
    if line.startswith("IP:"):
        parse_ip(u_list)
    elif line.startswith("GROUP:"):
        #print("parse_group")
        parse_group(u_list)
    elif line.startswith("GROUP_EXT:"):
        parse_group_ext(u_list)
    else:
        #print("parse_unit")
        parse_base_unit(u_list)

def parse_cfg():
    print("parse_cfg", global_path+"cfg/reg.cfg")
    global IP_NAME, GROUP_NAME
    with open(global_path+"cfg/reg.cfg", "r") as f:
        for l in f.readlines():
            l = l.lstrip(" ").lstrip("\t").rstrip("\n")
            if(len(l) == 0):
                continue
            parse_line(l)