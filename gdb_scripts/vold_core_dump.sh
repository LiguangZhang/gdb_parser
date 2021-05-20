#!/bin/bash
core_dump_path="../core/vold_core_dump"
symbol_root_path="../symbols/"
debug_elf_symbol_path="../symbols/system/bin/vold"

../../linux-x86/bin/gdb \
  -ex "file $debug_elf_symbol_path" \
  -ex "set pagination off" \
  -ex "core $core_dump_path" \
  -ex "set sysroot $symbol_root_path" \
  -ex "source ../gdb_scudo_driver.py" \
  -ex "scuparse" \

