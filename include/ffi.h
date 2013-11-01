#ifndef __KTAP_FFI_H__
#define __KTAP_FFI_H__

#include <stddef.h>

//@TODO add struct in cp2  25.10 2013 (houqp)
typedef enum {
	/* 0 - 4 */
	KTAP_CDVOID,
	KTAP_CDCHAR,
	KTAP_CDUCHAR,
	KTAP_CDUSHORT,
	KTAP_CDSHORT,
	/* 5 - 10 */
	KTAP_CDUINT,
	KTAP_CDINT,
	KTAP_CDULONG,
	KTAP_CDLONG,
	KTAP_CDULLONG,
	KTAP_CDLLONG,
	/* 11 - 13 */
	KTAP_CDPTR,
	KTAP_CDFUNC,
	KTAP_CDUNKNOWN,
} cdata_type;

#define NUM_CDATAS ((int)KTAP_CDUNKNOWN)


typedef struct csymbol_func {
	void *addr;
	int arg_nr;
	cdata_type *arg_types;
	cdata_type ret_type;
	int bytes;
} csymbol_func;

/*
 * used for symbol array;
 */
typedef struct csymbol {
	const char *name;
	cdata_type type;
	union {
		csymbol_func f;
	} u;
} csymbol;



typedef struct cdata_int {
	int val;
} cdata_int ;

typedef struct cdata_func {
	csymbol *proto;
} cdata_func;


#define csym_type(s) ((s)->type)
#define csym_name(s) ((s)->name)
#define csym_getf(s) ((s)->u.f)

#define cd_type(cd) ((cd)->type)
#define cd_getf(cd) ((cd)->u.f)
#define cd_getfsym(cd) (cd_getf(cd).proto)
#define cd_setfsym(cd, sym) (cd_getfsym(cd) = (sym))



#ifdef __KERNEL__
/* ffi type used in ffi module */
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
	FFI_POINTER,
	FFI_UNKNOWN,
} ffi_type;
#define NUM_FFI_TYPE ((int)FFI_UNKNOWN)

typedef struct {
	size_t size;
	size_t alignment;
	const char *name;
} ffi_mode;
extern const ffi_mode const ffi_type_modes[];

#define ffi_type_size(t) (ffi_type_modes[t].size)
#define ffi_type_alignment(t) (ffi_type_modes[t].alignment)
#define ffi_type_name(t) (ffi_type_modes[t].name)

#endif /* for __KERNEL__ */

#endif
