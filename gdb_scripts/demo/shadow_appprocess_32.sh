#!/bin/bash
symbol_path=
core_dump_file=
../../../linux-x86/bin/gdb \
  -ex "file {symbol_path}/system/bin/app_process64" \
  -ex "core {core_dump_file}" \
  -ex "set sysroot {symbol_path}" \
  -ex "source ../../gdb_scudo_driver.py" \
  -ex "scuparse"

