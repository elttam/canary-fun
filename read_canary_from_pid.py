#!/usr/bin/python2
#
# Use Auxiliary Vector and `/proc/<pid>/mem` syscall to dump the canary
# of a PID.
#
# Execute with:
# $ ./read_canary_from_pid.py <PID>
#
# @_hugsy_
#
# Copyright (c) 2017 elttam
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from __future__ import print_function
import sys, struct, platform

AT_RANDOM = 25

if platform.architecture()[0]=='64bit':
    L = 8
    F = "<Q"
else:
    L = 4
    F = "<4"

def get_at_random_address(pid):
    res = None
    with open("/proc/{}/auxv".format(pid)) as f:
        while True:
            k = struct.unpack(F, f.read(L))[0]
            if k<=0:
                break

            v = struct.unpack(F, f.read(L))[0]
            if k==AT_RANDOM:
                res = v
                break
    return res


def read_memory(pid, addr, n):
    with open("/proc/{}/mem".format(pid)) as f:
        f.seek(addr)
        return f.read(n)


if __name__ == "__main__":
    if len(sys.argv)!=2 or not sys.argv[1].isdigit():
        print("[-] Syntax: {} <PID>".format(sys.argv[0]))
        sys.exit(1)

    pid = int(sys.argv[1])
    addr = get_at_random_address(pid)
    print("[+] at_random={:#x}".format(addr))

    canary = read_memory(pid, addr, L)
    canary = struct.unpack(F, canary)[0]
    canary&= ~0xff
    print("[+] canary for pid={:d} is {:#x}".format(pid, canary))
