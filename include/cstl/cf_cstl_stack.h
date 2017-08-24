// cf_cstl_stack.h

#ifndef __CF_CSTL_STACK_H
#define __CF_CSTL_STACK_H

#include "cf_cstl.h"
#include "cf_cstl_iterator.h"


#define c_stack				_c_stack
#define c_pstack			_c_pstack
#define c_stack_create		__c_stack
#define c_stack_destroy		__c_kcats
#define c_stack_assign		_c_stack_assign
#define c_stack_empty		_c_stack_empty
#define c_stack_size		_c_stack_size
#define c_stack_top			_c_stack_top
#define c_stack_push		_c_stack_push
#define c_stack_pop			_c_stack_pop
#define c_stack_equal		_c_stack_equal
#define c_stack_less		_c_stack_less


typedef struct c_stack
{
	void * _l;
} c_stack, * c_pstack;

void __c_stack(c_pstack thiz, COMPARER pcmp);
void __c_kcats(c_pstack thiz);
c_pstack c_stack_assign(c_pstack thiz, const c_pstack S);
c_bool c_stack_empty(c_pstack thiz);
size_type c_stack_size(c_pstack thiz);
value_type c_stack_top(c_pstack thiz);
void c_stack_push(c_pstack thiz, const value_type val);
void c_stack_pop(c_pstack thiz);
c_bool c_stack_equal(c_pstack thiz, const c_pstack S);
c_bool c_stack_less(c_pstack thiz, const c_pstack S);


#endif /* __CF_CSTL_STACK_H */

