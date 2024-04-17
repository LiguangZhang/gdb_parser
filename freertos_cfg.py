from capstone import *
from capstone.mips import *

configMAX_PRIORITIES = 5
EPC_OFFSET = 124
RA_OFFSET = 120
SP_OFFSET = 160
CPU_NUMBERS = 2
arch = CS_ARCH_MIPS
mode = CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN
md = Cs(arch, mode)