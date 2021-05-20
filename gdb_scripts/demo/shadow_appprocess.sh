#!/bin/bash
symbol_path=/home/mi/work_space/miui-r-venus-dev/out/target/product/venus/symbols
code_dump_path=/home/mi/work_space/miui-r-venus-dev/core/system_server_core
../../../linux-x86/bin/gdb \
  -ex "file ${symbol_path}/system/bin/app_process64" \
  -ex "core ${code_dump_path}" \
  -ex "set sysroot ${symbol_path}" \

