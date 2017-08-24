// cf_cstl_queue.h

#ifndef __CF_CSTL_QUEUE_H
#define __CF_CSTL_QUEUE_H

#include "cf_cstl.h"
#include "cf_cstl_iterator.h"


#define c_queue				_c_queue
#define c_pqueue			_c_pqueue
#define c_queue_create		__c_queue
#define c_queue_destroy		__c_eueuq
#define c_queue_assign		_c_queue_assign
#define c_queue_empty		_c_queue_empty
#define c_queue_size		_c_queue_size
#define c_queue_front		_c_queue_front
#define c_queue_back		_c_queue_back
#define c_queue_push		_c_queue_push
#define c_queue_pop			_c_queue_pop
#define c_queue_equal		_c_queue_equal
#define c_queue_less		_c_queue_less


typedef struct c_queue
{
	void * _l;
} c_queue, * c_pqueue;


void __c_queue(c_pqueue thiz, COMPARER pcmp);
void __c_eueuq(c_pqueue thiz);
c_pqueue c_queue_assign(c_pqueue thiz, const c_pqueue Q);
c_bool c_queue_empty(c_pqueue thiz);
size_type c_queue_size(c_pqueue thiz);
value_type c_queue_front(c_pqueue thiz);
value_type c_queue_back(c_pqueue thiz);
void c_queue_push(c_pqueue thiz, const value_type val);
void c_queue_pop(c_pqueue thiz);
c_bool c_queue_equal(c_pqueue thiz, const c_pqueue Q);
c_bool c_queue_less(c_pqueue thiz, const c_pqueue Q);


#endif /* __CF_CSTL_QUEUE_H */

