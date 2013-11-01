/*
 * ffi_symbol.c - ktapvm kernel module ffi symbol submodule
 *
 * This file is part of ktap by Jovi Zhangwei.
 *
 * Copyright (C) 2012-2013 Jovi Zhangwei <jovi.zhangwei@gmail.com>.
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


#include "../../include/ktap.h"
#include "../../include/ktap_types.h"

static int sym_cnt; /* number of loaded symbols */
static ktap_table *ffi_table;
static ktap_table *ffi_cdef_table;
static csymbol *ffi_syms;


void add_ffi_func_to_ctable(ktap_state *ks, csymbol *fsym)
{
	ktap_value func_name, fv;
	ktap_cdata *cd;

	set_cdata(&fv, kp_newobject(ks, KTAP_CDATA, sizeof(ktap_cdata), NULL));
	cd = cdvalue(&fv);
	cd_type(cd) = KTAP_CDFUNC;
	cd_setfsym(cd, fsym);

	set_string(&func_name, kp_tstring_new(ks, csym_name(fsym)));
	kp_table_setvalue(ks, ffi_table, &func_name, &fv);
}

static inline int is_valid_cfunc_def(const ktap_table *sym_def)
{
	return (sym_def->sizearray >= 1);
}

int register_ffi_func(ktap_state *ks, const char *name, void *faddr,
		ktap_table *sym_def, csymbol *cs)
{
	int i, arraysize, arg_nr = 0;
	cdata_type *argtype_arr;

	argtype_arr = NULL;
	/* ok, we found a function definition */
	kp_verbose_printf(ks, "registering C function: %s\n", name);
	csym_type(cs) = KTAP_CDFUNC;
	/*  set function name */
	csym_name(cs) = name;
	/*  set function address */
	kp_verbose_printf(ks, "function address %p\n", faddr);
	csym_getf(cs).addr = faddr;
	/* set function prototype */
	/* first array element stores return type */
	csym_getf(cs).ret_type = nvalue(&sym_def->array[0]);
	/* populate argument types */
	arraysize = sym_def->sizearray;
	if (arraysize > 1) {
		/* get table array size */
		for (i = 1; i < arraysize; i++)
			if (is_nil(&sym_def->array[i]))
				break;
		/* since first element is return type, real argument number
		 * should be arraysize -1 */
		arg_nr = i - 1;
		argtype_arr = kp_malloc(ks, arg_nr*sizeof(cdata_type));
		for (i = 0; i < arg_nr; i++) {
			/* argument type starts from second element */
			argtype_arr[i] = nvalue(&sym_def->array[i+1]);
		}
	} else if (arraysize == 1) {
		arg_nr = 0;
	}
	csym_getf(cs).arg_types = argtype_arr;
	csym_getf(cs).arg_nr = arg_nr;

	add_ffi_func_to_ctable(ks, cs);

	return 0;
}

void ffi_load_sym(ktap_state *ks)
{
	int i, re, node_sz;
	ktap_table *sym_def;
	ktap_value key_type, key_addr;
	const ktap_value *sym_type, *addr;
	csymbol *cs;

	set_string(&key_type, kp_tstring_new(ks, "type"));
	set_string(&key_addr, kp_tstring_new(ks, "addr"));

	node_sz = kp_table_sizenode(ks, ffi_cdef_table);
	if (node_sz <= 0)
		return;
	sym_cnt = 0;

	ffi_syms = kp_malloc(ks, node_sz*sizeof(csymbol));
	memset(ffi_syms, 0, node_sz*sizeof(csymbol));

	/* iterate through each key(symbol) */
	for (i = 0; i < node_sz; i++) {
		ktap_tnode *n = &ffi_cdef_table->node[i];

		if (is_nil(kp_table_node_gkey(n)))
			continue;

		sym_def = hvalue(kp_table_node_gval(n));
		sym_type = kp_table_get(sym_def, &key_type);
		/* symbol type must be a number */
		if (!is_number(sym_type))
			continue;

		cs = &ffi_syms[sym_cnt];
		switch (nvalue(sym_type)) {
		case KTAP_CDFUNC:
			if (!is_valid_cfunc_def(sym_def)) {
				kp_verbose_printf(ks,
					"invalid function definition!\n");
				continue;
			}

			addr = kp_table_get(sym_def, &key_addr);
			re = register_ffi_func(ks,
					svalue(kp_table_node_gkey(n)),
					(void *)nvalue(addr), sym_def, cs);
			if (re < 0)
				continue;
			break;
		default:
			kp_verbose_printf(ks, "unsupported C symbol type!\n");
			continue;
			break;
		}

		sym_cnt++;
	}
}

void setup_kp_ffi_symbol_table(ktap_state *ks)
{
	ktap_table *registry;
	ktap_value ffi_lib_name, ffi_mt, cdef_name, cdef_mt;
	const ktap_value *gt = kp_table_getint(hvalue(&G(ks)->registry),
					       KTAP_RIDX_GLOBALS);

	ffi_table = kp_table_new(ks);
	ffi_cdef_table = kp_table_new(ks);

	/* insert cdef table to ffi table */
	set_table(&cdef_mt, ffi_cdef_table);
	set_string(&cdef_name, kp_tstring_new(ks, "cdef"));
	kp_table_setvalue(ks, ffi_table, &cdef_name, &cdef_mt);

	/* insert ffi table to global table */
	set_table(&ffi_mt, ffi_table);
	set_string(&ffi_lib_name, kp_tstring_new(ks, "C"));
	registry = hvalue(gt);
	kp_table_setvalue(ks, registry, &ffi_lib_name, &ffi_mt);
}

void kp_ffi_free_symbol(ktap_state *ks)
{
	int i;
	csymbol *cs;

	for (i = 0; i < sym_cnt; i++) {
		cs = &ffi_syms[i];
		switch (csym_type(cs)) {
		case KTAP_CDFUNC:
			if (csym_getf(cs).arg_types) {
				kp_free(ks, csym_getf(cs).arg_types);
			}
			break;
		default:
			continue;
		}
	}

	if (ffi_syms)
		kp_free(ks, ffi_syms);
}
