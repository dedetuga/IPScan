// ipscan launcher for aarch64. Same role as launch-armv7hf.S: an ET_DYN stub
// that execve()s the static Go daemon so classic ACAP start scripts accept it.
	.text
	.globl	_start
	.type	_start, %function
_start:
	ldr	x19, [sp]		// argc
	add	x20, sp, #8		// argv
	add	x21, x20, x19, lsl #3
	add	x21, x21, #8		// envp = argv + (argc+1)*8
	adr	x0, path_abs
	mov	x1, x20
	mov	x2, x21
	mov	x8, #221		// __NR_execve
	svc	#0
	adr	x0, path_rel
	mov	x1, x20
	mov	x2, x21
	mov	x8, #221
	svc	#0
	mov	x0, #2
	adr	x1, msg
	mov	x2, #(msg_end - msg)
	mov	x8, #64			// __NR_write
	svc	#0
	mov	x0, #127
	mov	x8, #93			// __NR_exit
	svc	#0
path_abs:
	.asciz	"@REAL_BIN@"
path_rel:
	.asciz	"bin/ipscan"
msg:
	.ascii	"ipscan launcher: cannot exec @REAL_BIN@\n"
msg_end:
	.balign	4
	.section .note.GNU-stack,"",%progbits
