import gdb
from gdb_common import *
from freertos_class import *
import utils
from capstone import *
from capstone.mips import *
import dump_stack
from freertos_cfg import *

def parse_task(task_item_str, stats, sub_item_index=0xffff):
    global total_ticks
    task_addr = hex(int(str(get_value(task_item_str)).split(" ")[0], 16))
    task_name_str = "(*(TCB_t*){})->pcTaskName".format(task_item_str)
    task_priority_str = "(*(TCB_t*){})->uxPriority".format(task_item_str)
    task_core_id_str = "(*(TCB_t*){})->xCoreID".format(task_item_str)
    task_rcore_id_str = "(*(TCB_t*){})->rCoreID".format(task_item_str)
    task_base_priority_str = "(*(TCB_t*){})->uxBasePriority".format(task_item_str)
    task_uxCriticalNesting_str = "(*(TCB_t*){})->uxCriticalNesting".format(task_item_str)
    task_pxTopOfStack_str = "(*(TCB_t*){})->pxTopOfStack".format(task_item_str)
    task_ulRunTimeCounter_str = "(*(TCB_t*){})->ulRunTimeCounter".format(task_item_str)
    task_stackend_str = "(*(TCB_t*){})->pxStack".format(task_item_str)

    # print(task_name_str)
    task_name_complex = str(get_value(task_name_str)).split(",")[0].lstrip("\"")
    task_name = task_name_complex[:task_name_complex.find('\\000')]
    if sub_item_index == 0xffff:
        task_priority = symbol_int_value(task_priority_str)
    else:
        task_priority = sub_item_index
    task_base_priority = symbol_int_value(task_base_priority_str)
    task_uxCriticalNesting = symbol_int_value(task_uxCriticalNesting_str)
    task_core_id = hex(symbol_int_value(task_core_id_str))
    task_rcore_id = symbol_int_value(task_rcore_id_str)
    task_pxTopOfStack = str(get_value(task_pxTopOfStack_str)).split(" ")[0]
    task_epc = read_word(int(task_pxTopOfStack, 16) + EPC_OFFSET)
    task_ra = read_word(int(task_pxTopOfStack, 16) + RA_OFFSET)
    task_sp = int(task_pxTopOfStack, 16) + SP_OFFSET
    task_stackend = str(get_value(task_stackend_str)).split(" ")[0]
    task_free_space = int(task_pxTopOfStack, 16) - int(task_stackend, 16)
    task_ulRunTimeCounter = symbol_int_value(task_ulRunTimeCounter_str)
    task_cpu_percent = "{:4.1f}%".format(task_ulRunTimeCounter*100/float(total_ticks))
    task = TASK(task_addr, task_name, task_core_id, task_rcore_id, task_priority, task_base_priority,
        task_uxCriticalNesting, task_pxTopOfStack, hex(task_epc), hex(task_sp), hex(task_ra), 
        task_free_space, task_ulRunTimeCounter, task_cpu_percent, stats)
    return task


def parse_task_list(list_name, stats, sub_item_index=0xffff):
    global taskstats
    task_dict = taskstats.task_dict
    item_index = 0
    task_list = []
    uxNumerofItems_str = list_name + ".uxNumberOfItems"
    uxNumerofItems = symbol_int_value(uxNumerofItems_str)
    skip_end_flag = False
    while item_index < uxNumerofItems:
        # print(item_index, uxNumerofItems)
        task_list_item_str = list_name + '.pxIndex' + item_index * '->pxPrevious'
        list_item_value_str = task_list_item_str + '.xItemValue'
        # print(list_item_value_str)
        # print(symbol_int_value(list_item_value_str))
        if symbol_int_value(list_item_value_str) == 0xffffffff and not skip_end_flag:
            item_index = item_index + 1;
            uxNumerofItems = uxNumerofItems + 1;
            skip_end_flag = True
            # print(j, uxNumerofItems)
            continue
        item_index = item_index + 1;
        task_item_str = task_list_item_str + '.pvOwner'
        task = parse_task(task_item_str, stats, sub_item_index)
        task_list.append(task)
        task_dict[task.addr] = task
    # print("parse_task_list end", list_name)
    return task_list

def parse_ready_list():
    global taskstats
    ready_lists = taskstats.ready_lists
    current_task_list = taskstats.current_task_list
    for i in range(CPU_NUMBERS):
        current_task_str = "pxCurrentTCB[{}]".format(i)
        current_task_addr = hex(int(str(get_value(current_task_str)).split(" ")[0], 16))
        current_task_list.append(current_task_addr)
    for i in range(configMAX_PRIORITIES):
        ready_lists_str = "pxReadyTasksLists[{}]".format(i)
        ready_list = parse_task_list(ready_lists_str, "READY", i)
        ready_lists.append(ready_list)

def parse_delay_list():
    global taskstats
    delay1_list_str = "pxDelayedTaskList"
    delay2_list_str = "pxOverflowDelayedTaskList"
    taskstats.delay1_list = parse_task_list(delay1_list_str, "DELAY")
    taskstats.delay2_list = parse_task_list(delay2_list_str, "OVER_DELAY")

def parse_suspend_list():
    global taskstats
    suspend_list_str = "xSuspendedTaskList"
    taskstats.suspend_list = parse_task_list(suspend_list_str, "SUSPEND")

def parse_current_tcb():
    global taskstats
    task_dict = taskstats.task_dict
    for i in range(CPU_NUMBERS):
        item_str = "pxCurrentTCB[{}]".format(i)
        task = parse_task(item_str, "RUNNING")
        task_dict[task.addr] = task
    
def parse():
    global taskstats, ready_lists, delay1_list, delay2_list, task_dict, total_ticks
    total_ticks = symbol_int_value("xTotalTicks")
    ready_lists = []
    delay1_list = []
    delay2_list = []
    suspend_list = []
    task_dict = {}
    current_task_list = []
    taskstats = TASK_STATS(ready_lists, delay1_list, delay2_list, suspend_list, task_dict, current_task_list)
    # # print("parse_current_tcb()")
    # parse_current_tcb()
    # print("parse_ready_list()")
    parse_ready_list()
    # print("parse_delay_list()")
    parse_delay_list()
    # print("parse_suspend_list()")
    parse_suspend_list()
    # print("end")

def dump_tasks_clear_cache():
    clear_cache()
    parse()
    dump_tasks()

def dump_task_stack(arg):
    sp = int(arg.split(" ")[0], 16)
    epc = int(arg.split(" ")[1], 16)
    ra = int(arg.split(" ")[2], 16)
    print(dump_stack.dump_caller(sp, epc, ra))

def dump_tasks():
    global taskstats
    task_dict = taskstats.task_dict
    current_task_list = taskstats.current_task_list
    table = [("addr", "name", "core_id", "rcore_id", "priority", "bpriority", "counter", 
                "percent", "free_space", "stats")]
    for k,task in task_dict.items():
        if k in current_task_list:
            addr = "* " + task.addr
        else:
            addr = "  " + task.addr
        table.append((addr, task.task_name, task.core_id, task.rcore_id, task.task_priority,
                task.task_base_priority, task.runtime_counter, 
                task.cpu_percent, task.free_space, task.task_stats))
    print(utils.assemble_table(table))

def dump_task(arg):
    global taskstats
    task_dict = taskstats.task_dict
    current_task_list = taskstats.current_task_list
    key = hex(int(arg, 16))
    table = [("addr", "name", "core_id", "rcore_id", "priority", "bpriority", "counter", 
                "percent", "free_space", "stats")]
    if key in task_dict:
        task = task_dict[key]
        if task.task_stack is None:
            task_stack = dump_stack.dump_caller(int(task.sp,16), int(task.epc,16), int(task.ra,16))
            task.update_stack(task_stack)
        if key in current_task_list:
            addr = "* " + task.addr
        else:
            addr = "  " + task.addr
        table.append((addr, task.task_name, task.core_id, task.rcore_id, task.task_priority,
                task.task_base_priority, task.runtime_counter, 
                task.cpu_percent, task.free_space, task.task_stats))
        print(utils.assemble_table(table))
        print(task.task_stack)

def dump_list(arg):
    # arg = "pxReadyTasksLists[1]"
    uxNumerofItems_str =  arg + ".uxNumberOfItems"
    uxNumerofItems = symbol_int_value(uxNumerofItems_str)
    for i in range(uxNumerofItems + 1):
        task_name_str = "(*(TCB_t*){}->pxIndex{}->pvOwner)->pcTaskName".format(arg, i*"->pxNext")
        core_id_str = "(*(TCB_t*){}->pxIndex{}->pvOwner)->xCoreID".format(arg, i*"->pxNext")
        handle_str = "{}->pxIndex{}->pvOwner".format(arg, i*"->pxNext")
        task_addr = hex(int(str(get_value(handle_str)).split(" ")[0], 16))
        
        task_name_complex = str(gdb.parse_and_eval(task_name_str)).split(",")[0].lstrip("\"")
        task_name = task_name_complex[:task_name_complex.find('\\000')]
        core_id = hex(symbol_int_value(core_id_str))
        print(i, task_name, core_id, task_addr)
        