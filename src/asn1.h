#ifndef SRC_ASN1_H_
#define SRC_ASN1_H_

// XXX remember the vulnerability with some libasn1fort object

#include <stdbool.h>
#include <libasn1fort/ANY.h>
#include <libasn1fort/BIT_STRING.h>
#include <libasn1fort/Extension.h>
#include <libasn1fort/INTEGER.h>
#include <libasn1fort/Name.h>
#include <libasn1fort/OBJECT_IDENTIFIER.h>
#include <libasn1fort/OCTET_STRING.h>
#include <libasn1fort/Time.h>
#include <libasn1fort/GeneralizedTime.h>

#include "alloc.h"
#include "print.h"

#define INIT_ASN1_ARRAY(arr, n, type) do {				\
		size_t i;						\
									\
		(arr)->count = n;					\
		(arr)->size = (arr)->count * sizeof(type *);		\
		(arr)->array = pmalloc((arr)->size);			\
		if (!(arr)->array)					\
			enomem;						\
									\
		for (i = 0; i < (arr)->count; i++)			\
			(arr)->array[i] = pzalloc(sizeof(type));	\
	} while (0)

void init_8str(OCTET_STRING_t *, char const *);
INTEGER_t *intmax2INTEGER(intmax_t src);
void init_INTEGER(INTEGER_t *field, intmax_t value);
void init_oid(OBJECT_IDENTIFIER_t *, int const *);
ANY_t *create_null(void);
void init_name(Name_t *, char const *);
void init_any_str(ANY_t *, char const *);
void init_time(Time_t *, char const *);
void init_time_now(Time_t *);
void init_time_later(Time_t *);
Time_t *create_time(char const *);
void init_gtime(GeneralizedTime_t *, char const *);
void init_gtime_now(GeneralizedTime_t *);
void init_gtime_later(GeneralizedTime_t *);

void der_encode_any(const asn_TYPE_descriptor_t *, void *, ANY_t *);
void der_encode_8str(const asn_TYPE_descriptor_t *, void *, OCTET_STRING_t *);

void *decode_ber(const asn_TYPE_descriptor_t *, const void *, size_t);
void *decode_ext(const asn_TYPE_descriptor_t *, struct Extension *);

void exec_mkdir(char *);
void exec_mkdir_p(char const *, bool);
void asn1_write(char *, const asn_TYPE_descriptor_t *, const void *);

#endif /* SRC_ASN1_H_ */
