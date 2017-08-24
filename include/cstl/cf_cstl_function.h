// cf_cstl_function.h

#ifndef __CF_CSTL_FUNCTION_H_
#define __CF_CSTL_FUNCTION_H_

#include "cf_cstl_iterator.h"

#define c_unary_function		_c_unary_function
#define c_binary_function		_c_binary_function
#define c_unary_predicate		_c_unary_predicate
#define c_binary_predicate		_c_binary_predicate

#define c_unary_negate			_c_unary_negate
#define c_binary_negate			_c_binary_negate

#define c_identity              _c_identity
#define c_select1st             _c_select1st
#define c_select1stptr			_c_select1stptr

#define c_unary_adapt			_c_unary_adapt
#define c_binary_adapt			_c_binary_adapt

typedef value_type (*UNARY_FUNCTION)(value_type);
typedef value_type (*BINARY_FUNCTION)(value_type, value_type);
typedef c_bool (*UNARY_PREDICATE)(value_type);
typedef c_bool (*BINARY_PREDICATE)(value_type, value_type);
typedef c_bool (*PREDICATE)(value_type);


typedef struct c_unary_function c_unary_function;
typedef struct c_binary_function c_binary_function;

struct c_unary_function
{
	value_type (*O)(c_unary_function * thiz, value_type val);
	void * _l;
};

struct c_binary_fuction
{
	value_type (*O)(c_binary_function * thiz, value_type val1, value_type val2);
	void * _l;
};

typedef struct c_unary_predicate c_unary_predicate;
typedef struct c_binary_predicate c_binary_predicate;

struct c_unary_predicate
{
	c_bool (*O)(c_unary_predicate * thiz, value_type val);
	void * _l;
};

struct c_binary_predicate
{
	c_bool (*O)(c_binary_predicate * thiz, value_type val1, value_type val2);
	void * _l;
};


c_unary_predicate c_unary_negate(UNARY_PREDICATE unary_pred);
c_binary_predicate c_binary_negate(BINARY_PREDICATE binary_pred);

c_unary_function c_identity(void);
c_unary_function c_select1st(void);
c_unary_function c_select1stptr(void);

c_unary_predicate c_unary_adapt(UNARY_PREDICATE unary_pred);
c_binary_predicate c_binary_adapt(BINARY_PREDICATE binary_pred);

#endif /* __CF_CSTL_FUNCTION_H_ */

