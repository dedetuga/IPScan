#!/usr/bin/env python3
"""Emit the MIPS32r2 (o32, little-endian) launcher stub for a given target path.

This is the launcher proven on ARTPEC-5 / AXIS OS 9.70 by SSH Jump (Legacy):
a freestanding position-independent stub (no libc, no relocations) that
builds the target path on the stack and execve()s it, preserving argv/envp.

    python3 gen-mips.py /usr/local/packages/ipscan/bin/ipscan > launch-mips.S
"""
import sys

p = sys.argv[1].encode() + b'\0'
while len(p) % 4:
    p += b'\0'
words = [int.from_bytes(p[i:i+4], 'little') for i in range(0, len(p), 4)]
alloc = ((len(p) + 15) // 16) * 16
L = ['\t.abicalls', '\t.set\tnoreorder', '\t.text', '\t.globl\t__start',
     '\t.globl\t_start', '\t.ent\t_start', '_start:', '__start:',
     '\tlw\t$t0, 0($sp)',          # argc
     '\taddiu\t$a1, $sp, 4',       # argv
     '\taddiu\t$t1, $t0, 1',
     '\tsll\t$t1, $t1, 2',
     '\taddu\t$a2, $a1, $t1',      # envp = argv + (argc+1)*4
     '\taddiu\t$sp, $sp, -%d' % alloc]
for i, w in enumerate(words):
    L += ['\tli\t$t2, 0x%08x' % w, '\tsw\t$t2, %d($sp)' % (i * 4)]
L += ['\tmove\t$a0, $sp',          # path
      '\tli\t$v0, 4011',           # __NR_execve (o32)
      '\tsyscall', '\tnop',
      '\tli\t$a0, 127', '\tli\t$v0, 4001',  # __NR_exit
      '\tsyscall', '\tnop', '\t.end\t_start']
sys.stdout.write('\n'.join(L) + '\n')
