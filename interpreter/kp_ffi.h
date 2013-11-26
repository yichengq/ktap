#ifndef __KTAP_FFI_H__
#define __KTAP_FFI_H__

#include <stddef.h>
#include "../include/ktap_types.h"

#ifdef CONFIG_KTAP_FFI

typedef enum {
	FFI_VOID,
	FFI_UINT8,
	FFI_INT8,
	FFI_UINT16,
	FFI_INT16,
	FFI_UINT32,
	FFI_INT32,
	FFI_UINT64,
	FFI_INT64,
	FFI_PTR,
	FFI_FUNC,
	FFI_STRUCT,
	FFI_UNKNOWN,
} ffi_type;

#define NUM_FFI_TYPE ((int)FFI_UNKNOWN)

typedef struct {
	size_t size;
	size_t align;
	const char *name;
} ffi_mode;
extern const ffi_mode const ffi_type_modes[];

#define ffi_type_size(t) (ffi_type_modes[t].size)
#define ffi_type_align(t) (ffi_type_modes[t].align)
#define ffi_type_name(t) (ffi_type_modes[t].name)


#define CSYM_NAME_MAX_LEN 64

typedef struct csymbol csymbol;

typedef struct csymbol_func {
	void *addr;
	csymbol_id ret_id;
	int arg_nr;
	csymbol_id *arg_ids;
} csymbol_func;

typedef struct struct_member {
	char name[CSYM_NAME_MAX_LEN];
	csymbol_id id;
} struct_member;

typedef struct csymbol_struct {
	int memb_nr;
	struct_member *members;
	size_t size;			/* bytes used to store struct */
	/* alignment of the struct, 0 indicates uninitialization */
	size_t align;
} csymbol_struct;


/*
 * used for symbol array;
 */

typedef struct csymbol {
	char name[CSYM_NAME_MAX_LEN];
	ffi_type type;
	/* only used for non scalar C types */
	union {
		csymbol_id p;		/* for pointer */
		csymbol_func f;
		csymbol_struct st;
		csymbol_id td;		/* for typedef */
	} u;
} csymbol;

inline csymbol *ffi_get_csym_by_id(csymbol_id id);

static inline csymbol *id_to_csym(csymbol_id id)
{
	return ffi_get_csym_by_id(id);
}

#define csym_type(cs) ((cs)->type)

static inline char *csym_name(csymbol *cs)
{
	return cs->name;
}

/*
 * start of pointer symbol helper functions
 */
static inline csymbol_id csym_ptr_deref_id(csymbol *cs)
{
	return cs->u.p;
}

static inline csymbol *csym_ptr_deref(csymbol *cs)
{
	return id_to_csym(csym_ptr_deref_id(cs));
}

static inline void csym_set_ptr_deref(csymbol *cs, csymbol_id id)
{
	cs->u.p = id;
}

/*
 * start of function symbol helper functions
 */
static inline csymbol_func *csym_func(csymbol *cs)
{
	return &cs->u.f;
}

static inline csymbol_id *csymf_arg_ids(csymbol_func *csf)
{
	return csf->arg_ids;
}

static inline int csymf_arg_nr(csymbol_func *csf)
{
	return csf->arg_nr;
}

static inline int *csym_func_arg_ids(csymbol *cs)
{
	return csymf_arg_ids(csym_func(cs));
}

static inline csymbol *csymf_arg(csymbol_func *csf, int idx)
{
	return id_to_csym(csf->arg_ids[idx]);
}

static inline csymbol_id csymf_ret_id(csymbol_func *csf)
{
	return csf->ret_id;
}

static inline csymbol *csymf_ret(csymbol_func *csf)
{
	return id_to_csym(csf->ret_id);
}

static inline csymbol *csym_func_arg(csymbol *cs, int idx)
{
	return csymf_arg(csym_func(cs), idx);
}

static inline void *csymf_addr(csymbol_func *csf)
{
	return csf->addr;
}

static inline void *csym_func_addr(csymbol *cs)
{
	return csymf_addr(csym_func(cs));
}

/*
 * start of struct symbol helper functions
 */
static inline csymbol_struct *csym_struct(csymbol *cs)
{
	return &cs->u.st;
}

static inline csymbol *csymst_mb(csymbol_struct *csst, int idx)
{
	return id_to_csym(csst->members[idx].id);
}

static inline csymbol *csym_struct_mb(csymbol *cs, int idx)
{
	return csymst_mb(csym_struct(cs), idx);
}

static inline int csymst_mb_nr(csymbol_struct *csst)
{
	return csst->memb_nr;
}


/*
 * following are used in ktap_cdata type
 */

typedef struct ktap_cdata ktap_cdata;

#define cd_csym_id(cd) ((cd)->id)
#define cd_set_csym_id(cd, id) (cd_csym_id(cd) = (id))
#define cd_csym(cd) (id_to_csym(cd_csym_id(cd)))
#define cd_type(cd) (cd_csym(cd)->type)

#define cd_int(cd) ((cd)->u.i)
#define cd_ptr(cd) ((cd)->u.p)
#define cd_struct(cd) ((cd)->u.st)


#ifdef __KERNEL__

struct ktap_state;
size_t csym_size(csymbol *sym);
size_t csym_align(csymbol *sym);
size_t csym_struct_offset(csymbol_struct *csst, int idx);
void init_csym_struct(csymbol_struct *csst);

#ifdef __x86_64

enum arg_status {
	IN_REGISTER,
	IN_MEMORY,
	IN_STACK,
};

#define ALIGN_STACK(v, a) ((void *)(ALIGN(((uint64_t)v), a)))
#define STACK_ALIGNMENT 8
#define REDZONE_SIZE 128
#define GPR_SIZE (sizeof(uint64_t))
#define MAX_GPR 6
#define MAX_GPR_SIZE (MAX_GPR * GPR_SIZE)

#define ffi_call(ks, cf, rvalue) ffi_call_x86_64(ks, cf, rvalue)

#else /* non-supported platform */

#define ffi_call(ks, cf, rvalue) ffi_call_unsupported(ks, cf, rvalue)

#endif /* end for platform-specific setting */

#endif /* for __KERNEL__ */


void ffi_set_csym_arr(ktap_state *ks, int cs_nr, csymbol *new_arr);
csymbol_id ffi_get_csym_id(char *name);
int kp_ffi_call(ktap_state *ks, csymbol_func *cf);
void setup_kp_ffi_symbol_table(ktap_state *ks);
void kp_ffi_free_symbol(ktap_state *ks);
ktap_cdata *kp_cdata_new(ktap_state *ks);
void kp_cdata_dump(ktap_state *ks, ktap_cdata *cd);
ktap_cdata *kp_cdata_new_ptr(ktap_state *ks, void *addr, csymbol_id id);
ktap_cdata *kp_cdata_new_struct(ktap_state *ks, void *val, csymbol_id id);

#else

static void __maybe_unused kp_ffi_free_symbol(ktap_state *ks)
{
	return;
}

#endif /* CONFIG_KTAP_FFI */

#endif /* __KTAP_FFI_H__ */
