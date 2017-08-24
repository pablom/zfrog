//cf_cstl_list.h

#ifndef __CF_CSTL_LIST_H
#define __CF_CSTL_LIST_H

#include "cf_cstl.h"
#include "cf_cstl_iterator.h"

#define c_list				_c_list
#define c_list_create		__c_list
#define c_list_destroy		__c_tsil
#define c_plist				_c_plist
#define c_list_begin		_c_list_begin
#define c_list_end			_c_list_end
#define c_list_rbegin		_c_list_rbegin
#define c_list_rend			_c_list_rend
#define c_list_size			_c_list_size
#define c_list_empty		_c_list_empty
#define c_list_assign		_c_list_assign
#define c_list_front		_c_list_front
#define c_list_back			_c_list_back
#define c_list_push_front	_c_list_push_front
#define c_list_push_back	_c_list_push_back
#define c_list_pop_front	_c_list_pop_front
#define c_list_pop_back		_c_list_pop_back
#define c_list_swap			_c_list_swap
#define c_list_insert		_c_list_insert
#define c_list_insert2		_c_list_insert2
#define c_list_erase		_c_list_erase
#define c_list_erase2		_c_list_erase2
#define c_list_clear		_c_list_clear
#define c_list_splice		_c_list_splice
#define c_list_splice1		_c_list_splice1
#define c_list_splice2		_c_list_splice2
#define c_list_remove		_c_list_remove
#define c_list_unique		_c_list_unique
#define c_list_merge		_c_list_merge
#define c_list_sort			_c_list_sort
#define c_list_equal		_c_list_equal
#define c_list_less			_c_list_less


typedef struct c_list
{
    COMPARER _cmp;   
    void * _l;
} c_list, * c_plist;


void __c_list(c_plist thiz, COMPARER pcmp);
void __c_tsil(c_plist thiz);
c_iterator c_list_begin(c_plist thiz);
c_iterator c_list_end(c_plist thiz);
c_reverse_iterator c_list_rbegin(c_plist thiz);
c_reverse_iterator c_list_rend(c_plist thiz);
size_t c_list_size(c_plist thiz);
c_bool c_list_empty(c_plist thiz);
c_plist c_list_assign(c_plist thiz, const c_plist L);
value_type c_list_front(c_plist thiz);
value_type c_list_back(c_plist thiz);
void c_list_push_front(c_plist thiz, const value_type val);
void c_list_push_back(c_plist thiz, const value_type val);
void c_list_pop_front(c_plist thiz);
void c_list_pop_back(c_plist thiz);
void c_list_swap(c_plist thiz, c_plist L);
c_iterator c_list_insert(c_plist thiz, c_iterator pos, const value_type val);
void c_list_insert2(c_plist thiz, c_iterator pos, c_iterator first, c_iterator last);
c_iterator c_list_erase(c_plist thiz, c_iterator pos);
c_iterator c_list_erase2(c_plist thiz, c_iterator first, c_iterator last);
void c_list_clear(c_plist thiz);
void c_list_splice(c_plist thiz, c_iterator pos, c_plist L);
void c_list_splice1(c_plist thiz, c_iterator pos, c_plist L, c_iterator i);
void c_list_splice2(c_plist thiz, c_iterator pos, c_plist L, c_iterator first, c_iterator last);
void c_list_remove(c_plist thiz, value_type val);
void c_list_unique(c_plist thiz);
void c_list_merge(c_plist thiz, c_plist L);
void c_list_sort(c_plist thiz);
c_bool c_list_equal(c_plist thiz, const c_plist L);
c_bool c_list_less(c_plist thiz, const c_plist L);



#endif /* __CF_CSTL_LIST_H */
