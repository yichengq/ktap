/*
 * ffi_call.c - foreign function calling library support for ktap
 *
 * This file is part of ktap by zhangwei(Jovi).
 *
 * Copyright (C) 2012-2013 zhangwei(Jovi) <jovi.zhangwei@gmail.com>.
 * See the COPYRIGHT file at the top-level directory of this distribution.
 *
 * ktap is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * ktap is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <linux/ctype.h>
#include <linux/slab.h>
#include "../../include/ffi.h"
#include "../../include/ktap.h"

static ffi_type cdata_to_ffi_type(cdata_type type)
{
	/*@TODO size should be architecture dependent, need to have different
	 * version for different arch in the future (houqp)*/
	switch(type) {
	case KTAP_CDVOID:
		return FFI_VOID;
	case KTAP_CDUCHAR:
		return FFI_UINT8;
	case KTAP_CDCHAR:
		return FFI_INT8;
	case KTAP_CDUSHORT:
		return FFI_UINT16;
	case KTAP_CDSHORT:
		return FFI_INT16;
	case KTAP_CDUINT:
		return FFI_UINT32;
	case KTAP_CDINT:
		return FFI_INT32;
	case KTAP_CDULONG:
	case KTAP_CDULLONG:
		return FFI_UINT64;
	case KTAP_CDLONG:
	case KTAP_CDLLONG:
		return FFI_INT64;
	case KTAP_CDPTR:
	case KTAP_CDFUNC:
		return FFI_POINTER;
	case KTAP_CDUNKNOWN:
		break;
	}

	/* NEVER reach here, silence compiler */
	return -1;
}

static int cdata_type_check(ktap_state *ks, cdata_type type, StkId arg, int idx)
{
	switch (ttypenv(arg)) {
	case KTAP_TLIGHTUSERDATA:
		if (type != KTAP_CDPTR) goto error;
		break;
	case KTAP_TBOOLEAN:
	case KTAP_TNUMBER:
		if (type != KTAP_CDCHAR && type != KTAP_CDUCHAR
		&& type != KTAP_CDUSHORT && type != KTAP_CDSHORT
		&& type != KTAP_CDUINT && type != KTAP_CDINT
		&& type != KTAP_CDULONG && type != KTAP_CDLONG
		&& type != KTAP_CDULLONG && type != KTAP_CDLLONG)
			goto error;
		break;
	case KTAP_TSTRING:
		if (type != KTAP_CDPTR) goto error;
		break;
	default:
		if (type != cdvalue(arg)->type) goto error;
	}
	return 0;

 error:
	kp_error(ks, "Error: Cannot convert to cdata_type %s for arg %d\n",
			ffi_type_name(cdata_to_ffi_type(type)), idx);
	return -1;
}

static void unpack_cdata(ktap_state *ks, cdata_type type,
		StkId arg, char *dst)
{
	size_t size = ffi_type_size(cdata_to_ffi_type(type));
	void *p;

	switch (ttypenv(arg)) {
	case KTAP_TBOOLEAN:
		memcpy(dst, &bvalue(arg), size);
		return;
	case KTAP_TLIGHTUSERDATA:
		memcpy(dst, pvalue(arg), size);
		return;
	case KTAP_TNUMBER:
		memcpy(dst, &nvalue(arg), size);
		return;
	case KTAP_TSTRING:
		p = &rawtsvalue(arg)->tsv + 1;
		memcpy(dst, &p, size);
		return;
	}

	switch (type) {
	case KTAP_CDVOID:
		kp_error(ks, "Error: Cannot copy data from void type\n");
		return;
	case KTAP_CDCHAR:
	case KTAP_CDUCHAR:
	case KTAP_CDUSHORT:
	case KTAP_CDSHORT:
	case KTAP_CDUINT:
	case KTAP_CDINT:
	case KTAP_CDULONG:
	case KTAP_CDLONG:
	case KTAP_CDULLONG:
	case KTAP_CDLLONG:
		memcpy(dst, &cdvalue(arg)->u.i.val, size);
		break;
	case KTAP_CDPTR:
	case KTAP_CDFUNC:
	case KTAP_CDUNKNOWN:
		kp_error(ks, "Error: Unsupport for cdata_type %s\n",
			ffi_type_name(cdata_to_ffi_type(type)));
	}

	return;
}

#ifdef __x86_64

#define ALIGN_STACK(v, a) ((void *)(ALIGN(((uint64_t)v), a)))
#define STACK_ALIGNMENT 8
#define GPR_SIZE (sizeof(uint64_t))
#define MAX_GPR 6
#define MAX_GPR_SIZE (MAX_GPR * GPR_SIZE)

extern void ffi_call_assem_x86_64(void *stack, void *temp_stack,
					void *rvalue, void *func_addr);

static void ffi_call_x86_64(ktap_state *ks, csymbol_func *cf, void *rvalue)
{
	int i;
	int gpr_nr;
	int bytes = 0; /* total bytes needed for arguments */
	char *stack, *stack_p, *arg_p, *gpr_p, *tmp_p;

	/* calculate bytes needed for stack */
	/* Currently, one argument can be put in a 64-bit register always */
	gpr_nr = 0;
	for (i = 0; i < cf->arg_nr; i++) {
		cdata_type actype = cf->arg_types[i];
		ffi_type aftype = cdata_to_ffi_type(actype);
		if (gpr_nr < MAX_GPR)
			gpr_nr++;
		else {
			bytes = ALIGN(bytes, ffi_type_alignment(aftype));
			bytes += ffi_type_size(aftype);
			bytes = ALIGN(bytes, STACK_ALIGNMENT);
		}
	}

	/* apply space to fake stack for C function call */
	stack = kp_malloc(ks, MAX_GPR_SIZE + bytes + 6 * 8 + 128);
	/* 128 bytes below %rsp is red zone */
	stack_p = stack + 128;
	/* stack should be 16-bytes aligned */
	stack_p = ALIGN_STACK(stack_p, 16);
	/* save general purpose registers here */
	gpr_p = stack_p;
	memset(gpr_p, 0, MAX_GPR_SIZE);
	/* save arguments here */
	arg_p = gpr_p + MAX_GPR_SIZE;
	/* set additional space as temporary space */
	tmp_p = arg_p + bytes;

	/* copy arguments here */
	gpr_nr = 0;
	for (i = 0; i < cf->arg_nr; i++) {
		cdata_type actype = cf->arg_types[i];
		ffi_type aftype = cdata_to_ffi_type(actype);
		unpack_cdata(ks, actype, kp_arg(ks, i+1), tmp_p);
		if (gpr_nr < MAX_GPR) {
			memcpy(gpr_p, tmp_p, ffi_type_size(aftype));
			gpr_p += GPR_SIZE;
			gpr_nr++;
		} else {
			arg_p = ALIGN_STACK(arg_p, ffi_type_alignment(aftype));
			memcpy(arg_p, tmp_p, ffi_type_size(aftype));
			arg_p += ffi_type_size(aftype);
			arg_p = ALIGN_STACK(arg_p, STACK_ALIGNMENT);
		}
	}

	kp_verbose_printf(ks, "Number of register used: %d\n", gpr_nr);
	kp_verbose_printf(ks, "Stack location: %p %p %p %p\n", stack_p, gpr_p, arg_p, tmp_p);
	kp_verbose_printf(ks, "Address for return value: %p\n", rvalue);
	kp_verbose_printf(ks, "Function address: %p\n", cf->addr);
	ffi_call_assem_x86_64(stack_p, tmp_p, rvalue, cf->addr);
	kp_verbose_printf(ks, "Finish FFI call\n");

	kp_free(ks, stack);
	return;
}

#endif /* end for __x86_64 */

void ffi_set_return(ktap_state *ks, void *rvalue, cdata_type ret_type)
{
	/* push return value to ktap stack */
	switch (ret_type) {
	case KTAP_CDVOID:
		return;
	case KTAP_CDSHORT:
	case KTAP_CDINT:
	case KTAP_CDLONG:
	case KTAP_CDLLONG:
	case KTAP_CDUSHORT:
	case KTAP_CDCHAR:
	case KTAP_CDUCHAR:
	case KTAP_CDUINT:
	case KTAP_CDULONG:
	case KTAP_CDULLONG:
		set_number(ks->top, (ktap_number)rvalue);
		break;
	case KTAP_CDPTR:
	case KTAP_CDFUNC:
		/*@TODO handle pointer case in cp2  25.10 2013 (houqp)*/
		break;
	case KTAP_CDUNKNOWN:
		/*@TODO handle unknown type  25.10 2013 (houqp)*/
		break;
	}
	incr_top(ks);
}

/*
 * Call C into function
 * First argument should be function symbol address, argument types
 * and return type.
 * Left arguments should be arguments for calling the C function.
 * Types between Ktap and C are converted automatically.
 * Only support x86_64 stdcall for now
 */
void kp_ffi_call(ktap_state *ks, csymbol_func *cf)
{
	int i, arg_nr = cf->arg_nr;
	cdata_type *arg_types = cf->arg_types;
	ktap_closure *cl;
	void *rvalue;

	/* check stack status for C call */
	if (arg_nr != kp_arg_nr(ks)) {
		kp_error(ks, "wrong argument number %d\n", arg_nr);
		goto out;
	}

	/* maybe useful later, leave it here first */
	cl = clvalue(kp_arg(ks, arg_nr + 1));

	/* check the argument types */
	for (i = 0; i < arg_nr; i++) {
		StkId karg = kp_arg(ks, i + 1);
		cdata_type atype = arg_types[i];
		if (cdata_type_check(ks, atype, karg, i) < 0)
			goto out;
	}

#if __x86_64
	ffi_call_x86_64(ks, cf, &rvalue);
#else
	kp_error(ks, "not supported architecture.\n");
#endif

out:
	ffi_set_return(ks, rvalue, cf->ret_type);
	return;
}
