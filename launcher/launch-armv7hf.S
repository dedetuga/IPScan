@ ipscan launcher for armv7hf (ARM EABI, A32).
@
@ Classic ACAP start scripts (AXIS OS 9.x / 10.0-10.5) only start ET_DYN
@ (PIE) executables. Go cannot build a PIE for linux/arm without cgo, so the
@ package-root binary is this tiny position-independent stub: it execve()s the
@ static Go daemon, keeping PID, argv and envp (systemd / init scripts / pidof
@ keep working). No libc, no relocations; @REAL_BIN@ is filled in by build.sh.
	.syntax unified
	.arm
	.text
	.globl	_start
	.type	_start, %function
_start:
	ldr	r4, [sp]		@ argc
	add	r5, sp, #4		@ argv
	add	r6, r5, r4, lsl #2
	add	r6, r6, #4		@ envp = argv + (argc+1)*4
	adr	r0, path_abs
	mov	r1, r5
	mov	r2, r6
	mov	r7, #11			@ __NR_execve
	svc	#0
	adr	r0, path_rel		@ fallback: relative to the working directory
	mov	r1, r5
	mov	r2, r6
	mov	r7, #11
	svc	#0
	mov	r0, #2			@ stderr -> system log
	adr	r1, msg
	mov	r2, #(msg_end - msg)
	mov	r7, #4			@ __NR_write
	svc	#0
	mov	r0, #127
	mov	r7, #1			@ __NR_exit
	svc	#0
path_abs:
	.asciz	"@REAL_BIN@"
path_rel:
	.asciz	"bin/ipscan"
msg:
	.ascii	"ipscan launcher: cannot exec @REAL_BIN@\n"
msg_end:
	.align	2
	.section .note.GNU-stack,"",%progbits
