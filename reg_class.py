# -*- coding: UTF-8 -*-
class REG():
    def __init__(self, ip_dict, group_dict, unit_list):
        self.ip_dict = ip_dict
        self.group_dict = group_dict
        self.unit_list = unit_list
    
    def fill_ip(self, ip):
        self.ip_dict[ip.name] = ip
    
    def fill_group(self, group):
        self.group_dict[group.name] = group
    
    def fill_unit(self, unit):
        self.unit_list.append(unit)
    

class IP():
    def __init__(self, ip_name, ip_base_addr):
        self.name = ip_name
        self.base_addr = ip_base_addr

class GROUP():
    def __init__(self, g_name, offset, ip, addr):
        self.name = g_name
        self.offset = offset
        self.ip = ip
        self.addr = addr

class UNIT_INFO():
    def __init__(self, reg_name, offset, width, unit, g_name, ip_name, addr):
        self.reg_name = reg_name
        self.offset = offset
        self.off_str = "{}:{}".format(int(offset), int(offset)+int(width)-1) 
        self.width = width
        # 10进制 输出还是2进制输出 ...
        self.unit = unit
        self.g_name = g_name
        self.ip_name = ip_name
        self.addr = addr
        self.val = 0
        self.d_val = 0
    
    def update(self, val):
        self.val = val
        if(self.unit == "2"):
            self.d_val = r"b '"+str(bin(val))[2:]+r"'"
        elif(self.unit == "16"):
            self.d_val = hex(val)
        else:
            self.d_val = val

