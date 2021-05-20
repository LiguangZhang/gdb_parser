#!/bin/bash
symbol_path=
binary_path=
binary_name=

adb forward tcp:8888 tcp:8888
adb shell 'pidof gdbserver64 | xargs kill -9'
adb shell pidof $binary_name | awk '{print $1}' > pidfile.txt
adb push pidfile.txt /cache/

adb shell 'cat /cache/pidfile.txt | xargs gdbserver64 127.0.0.1:8888  --attach' &
aarch64-linux-android-gdb \
  -ex "target remote :8888" \
  -ex "set sysroot {symbol_path}/" \
  -se "{binary_path}" \
  -ex "source ../../gdb_scudo_driver.py" \
  -ex "scuparse"