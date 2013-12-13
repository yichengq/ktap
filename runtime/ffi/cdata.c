/*
 * cdata.c - support functions for ktap_cdata
 *
 * This file is part of ktap by Jovi Zhangwei
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


#include "../../include/ktap_types.h"
#include "../../include/ktap_ffi.h"
#include "../kp_obj.h"

ktap_cdata *kp_cdata_new(ktap_state *ks)
{
	ktap_cdata *cd;

	cd = &kp_newobject(ks, KTAP_TCDATA, sizeof(ktap_cdata), NULL)->cd;

	return cd;
}

/* argument len here indicates the length of array that is pointed to */
ktap_cdata *kp_cdata_new_ptr(ktap_state *ks, void *addr,
		int len, csymbol_id id)
{
	ktap_cdata *cd;
	size_t size;

	cd = kp_cdata_new(ks);
	cd_set_csym_id(cd, id);

	/* if val == NULL, allocate new empty space */
	if (addr == NULL) {
		/* TODO: free the space when exit the program unihorn(08.12.2013) */
		size = csym_size(ks, id_to_csym(ks, id));
		cd_ptr(cd) = kp_zalloc(ks, size * len);
		cd_ptr_allocated(cd) = 1;
	} else {
		cd_ptr(cd) = addr;
		cd_ptr_allocated(cd) = 0;
	}

	return cd;
}

void kp_cdata_free_ptr(ktap_state *ks, ktap_cdata *cd)
{
	if (cd_ptr_allocated(cd))
		kp_free(ks, cd_ptr(cd));
	cd_ptr(cd) = NULL;
}

ktap_cdata *kp_cdata_new_struct(ktap_state *ks, void *val, csymbol_id id)
{
	ktap_cdata *cd;
	size_t size;

	cd = kp_cdata_new(ks);
	cd_set_csym_id(cd, id);

	/* if val == NULL, allocate new empty space */
	if (val == NULL) {
		/* TODO: free the space when exit the program unihorn(08.12.2013) */
		size = csym_size(ks, id_to_csym(ks, id));
		cd_struct(cd) = kp_zalloc(ks, size);
	} else
		cd_struct(cd) = val;

	return cd;
}

void kp_cdata_dump(ktap_state *ks, ktap_cdata *cd)
{
	switch (cd_type(ks, cd)) {
	case FFI_PTR:
		kp_printf(ks, "pointer(%p)", cd_ptr(cd));
		break;
	default:
		kp_printf(ks, "unsupported cdata type %d!\n", cd_type(ks, cd));
	}
}
