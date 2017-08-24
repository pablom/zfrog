// cf_cstl_vector.h

#ifndef __CF_CSTL_VECTOR_H
#define __CF_CSTL_VECTOR_H

#include "cf_cstl.h"
#include "cf_cstl_iterator.h"

#define c_vector                _c_vector
#define c_pvector               _c_pvector
#define c_vector_create			__c_vector
#define c_vector_destroy		__c_rotcev
#define c_vector_begin			_c_vector_begin 
#define c_vector_end			_c_vector_end
#define c_vector_rbegin			_c_vector_rbegin
#define c_vector_rend			_c_vector_rend
#define c_vector_size			_c_vector_size
#define c_vector_max_size		_c_vector_max_size
#define c_vector_empty			_c_vector_empty
#define c_vector_at             _c_vector_at
#define c_vector_assign			_c_vector_assign
#define c_vector_reserve		_c_vector_reserve
#define c_vector_front			_c_vector_front
#define c_vector_back			_c_vector_back
#define c_vector_push_back		_c_vector_push_back
#define c_vector_pop_back		_c_vector_pop_back
#define c_vector_swap			_c_vector_swap
#define c_vector_insert			_c_vector_insert
#define c_vector_insert2		_c_vector_insert2
#define c_vector_fill_insert	_c_vector_fill_insert
#define c_vector_erase			_c_vector_erase
#define c_vector_erase2			_c_vector_erase2
#define c_vector_clear			_c_vector_clear
#define c_vector_resize			_c_vector_resize
#define c_vector_equal			_c_vector_equal
#define c_vector_less			_c_vector_less

typedef struct c_vector
{
    COMPARER _cmp;   
    void * _l;
} c_vector, * c_pvector;

void __c_vector(c_pvector thiz, COMPARER pcmp);
void __c_rotcev(c_pvector thiz);
c_iterator c_vector_begin(c_pvector thiz);
c_iterator c_vector_end(c_pvector thiz);
c_reverse_iterator c_vector_rbegin(c_pvector thiz);
c_reverse_iterator c_vector_rend(c_pvector thiz);
size_type c_vector_size(c_pvector thiz);
size_type c_vector_max_size(c_pvector thiz);
size_type c_vector_capacity(c_pvector thiz);
c_bool c_vector_empty(c_pvector thiz);
value_type c_vector_at(c_pvector thiz, size_type n);
c_pvector c_vector_assign(c_pvector thiz, const c_pvector V);
void c_vector_reserve(c_pvector thiz, size_t n);
value_type c_vector_front(c_pvector thiz);
value_type c_vector_back(c_pvector thiz);
void c_vector_push_back(c_pvector thiz, const value_type val);
void c_vector_pop_back(c_pvector thiz);
void c_vector_swap(c_pvector thiz, c_pvector V);
c_iterator c_vector_insert(c_pvector thiz, c_iterator pos, const value_type val);
void c_vector_insert2(c_pvector thiz, c_iterator pos, c_iterator first, c_iterator last);
void c_vector_fill_insert(c_pvector thiz, c_iterator pos, size_type n, const value_type val);
c_iterator c_vector_erase(c_pvector thiz, c_iterator pos);
c_iterator c_vector_erase2(c_pvector thiz, c_iterator first, c_iterator last);
void c_vector_clear(c_pvector thiz);
void c_vector_resize(c_pvector thiz, size_t n);
c_bool c_vector_equal(c_pvector thiz, const c_pvector V);
c_bool c_vector_less(c_pvector thiz, const c_pvector V);


#endif /* __CF_CSTL_VECTOR_H */
