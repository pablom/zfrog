// cf_cstl_stack.c

#include "cf_cstl_stack.h"
#include "cf_cstl_vector.h"
#include "cf_cstl_memory.h"


void __c_stack(c_pstack thiz, COMPARER pcmp)
{
	thiz->_l = __c_malloc(sizeof(c_vector));
	__c_vector((c_pvector)thiz->_l, pcmp);
}

void __c_kcats(c_pstack thiz)
{
	__c_rotcev((c_pvector)thiz->_l);
	__c_free((c_pvector)thiz->_l);
}

c_pstack c_stack_assign(c_pstack thiz, const c_pstack S)
{
	c_vector_assign((c_pvector)thiz->_l, (c_pvector)S->_l);
	return thiz;
}

c_bool c_stack_empty(c_pstack thiz)
{
	return c_vector_empty((c_pvector)thiz->_l);
}

size_type c_stack_size(c_pstack thiz)
{
	return c_vector_size((c_pvector)thiz->_l);
}

value_type c_stack_top(c_pstack thiz)
{
	return c_vector_back((c_pvector)thiz->_l);
}

void c_stack_push(c_pstack thiz, const value_type val)
{
	c_vector_push_back((c_pvector)thiz->_l, val);
}

void c_stack_pop(c_pstack thiz)
{
	c_vector_pop_back((c_pvector)thiz->_l);		
}

c_bool c_stack_equal(c_pstack thiz, const c_pstack S)
{
	return c_vector_equal((c_pvector)thiz->_l, (c_pvector)S->_l);
}

c_bool c_stack_less(c_pstack thiz, const c_pstack S)
{
	return c_vector_less((c_pvector)thiz->_l, (c_pvector)S->_l);
}
