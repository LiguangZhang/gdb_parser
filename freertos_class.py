# -*- coding: UTF-8 -*-
class TASK_STATS:
    def __init__(self, ready_lists, delay1_list, delay2_list, suspend_list, task_dict, current_task_list):
        self.ready_lists = ready_lists
        self.delay1_list = delay1_list
        self.delay2_list = delay2_list
        self.suspend_list = suspend_list
        self.task_dict = task_dict
        self.current_task_list = current_task_list

class TASK:
    def __init__(self, addr, task_name, core_id, rcore_id, task_priority, task_base_priority,
            task_uxCriticalNesting, task_pxTopOfStack, epc, sp, ra, 
            free_space, runtime_counter, cpu_percent, task_stats):
        self.addr = addr
        self.task_name = task_name
        self.core_id = core_id
        self.rcore_id = rcore_id
        self.task_priority = task_priority
        self.task_base_priority = task_base_priority
        self.task_uxCriticalNesting = task_uxCriticalNesting
        self.task_pxTopOfStack = task_pxTopOfStack
        self.epc = epc
        self.sp = sp
        self.ra = ra
        self.free_space = free_space
        self.runtime_counter = runtime_counter
        self.cpu_percent = cpu_percent
        self.task_stats = task_stats
        self.task_stack = None

    def update_stack(self, task_stack):
        self.task_stack = task_stack

