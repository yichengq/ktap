#ifdef __x86_64

	.file "x86_64.S"
	.text

/*	ffi_call_assem_x86_64(void *stack, void *temp_stack,
 *		void *rvalue, void *func_addr)
 *	@stack: base address of register values and new stack
 *	@temp_stack: stack to store temporary values
 *	@rvalue: where to put return value
 *	@func_addr: Function address
 */
	.align 2
	.globl	ffi_call_assem_x86_64
	.type	ffi_call_assem_x86_64,@function

ffi_call_assem_x86_64:
	movq	%rsp, %rax	/* save return address */
	/* move stuffs to temp memory region(void *temp_stack) */
	movq	%rdx, (%rsi)	/* save pointer to return value */
	movq	%rbp, 8(%rsi)	/* save %rbp */
	movq	%rax, 16(%rsi)
	movq	%rsi, %rbp	/* point %rbp to temp memory region */

	movq	%rcx, %r11	/* move function address to %r11 */

	movq	%rdi, %r10	/* set %r10 point to register region */
	movq	(%r10), %rdi	/* load registers */
	movq	8(%r10), %rsi
	movq	16(%r10), %rdx
	movq	24(%r10), %rcx
	movq	32(%r10), %r8
	movq	40(%r10), %r9
	leaq	48(%r10), %rsp

	callq	*%r11

	movq	16(%rbp), %rsp	/* restore return address */

	movq	(%rbp), %rdx	/* get pointer to return value */
	movq	%rax, (%rdx)	/* set return value */

	movq	8(%rbp), %rbp	/* restore rbp */

	retq

#endif /* end for __x86_64 */
