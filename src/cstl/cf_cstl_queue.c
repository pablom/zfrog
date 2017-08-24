// cf_cstl_queue.c

#include "cf_cstl_queue.h"
#include "cf_cstl_memory.h"
#include "cf_cstl_list.h"


void __c_queue(c_pqueue thiz, COMPARER pcmp)
{
	thiz->_l = __c_malloc(sizeof(c_list));
	__c_list((c_plist)thiz->_l, pcmp);
}

void __c_eueuq(c_pqueue thiz)
{
	__c_tsil((c_plist)thiz->_l);
	__c_free(thiz->_l);
}

c_pqueue c_queue_assign(c_pqueue thiz, const c_pqueue Q)
{	
	c_list_assign((c_plist)thiz->_l, (c_plist)Q->_l);
	return thiz;
}

c_bool c_queue_empty(c_pqueue thiz)
{
	return c_list_empty((c_plist)thiz->_l);
}

size_type c_queue_size(c_pqueue thiz)
{
	return c_list_size((c_plist)thiz->_l);
}

value_type c_queue_front(c_pqueue thiz)
{
	return c_list_front((c_plist)thiz->_l);
}

value_type c_queue_back(c_pqueue thiz)
{
	return c_list_back((c_plist)thiz->_l);
}

void c_queue_push(c_pqueue thiz, const value_type val)
{
	c_list_push_back((c_plist)thiz->_l, val);
}

void c_queue_pop(c_pqueue thiz)
{
	c_list_pop_front((c_plist)thiz->_l);
}

c_bool c_queue_equal(c_pqueue thiz, const c_pqueue Q)
{
	return c_list_equal((c_plist)thiz->_l, (c_plist)Q->_l);
}

c_bool c_queue_less(c_pqueue thiz, const c_pqueue Q)
{
	return c_list_less((c_plist)thiz->_l, (c_plist)Q->_l);
}
