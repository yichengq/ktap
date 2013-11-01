/*
 * ffi.c - ktapvm kernel module ffi library
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

static int kp_ffi_load_sym(ktap_state *ks)
{
	ffi_load_sym(ks);
	return 0;
}

static const ktap_Reg ffi_funcs[] = {
	{"load_sym", kp_ffi_load_sym},
	{NULL}
};

void kp_init_ffilib(ktap_state *ks)
{
	setup_kp_ffi_symbol_table(ks);
	kp_register_lib(ks, "ffi", ffi_funcs);
}
