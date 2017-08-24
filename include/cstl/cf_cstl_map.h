// cf_cstl_map.h

#ifndef __CF_CSTL_MAP_H_
#define __CF_CSTL_MAP_H_

#include "cf_cstl_tree.h"

#define c_map                   _c_map
#define c_pmap                  _c_pmap
#define c_map_create			__c_map
#define c_map_destroy			__c_pam
#define c_map_assign			_c_map_assign
#define c_map_begin             _c_map_begin
#define c_map_end               _c_map_end
#define c_map_rbegin			_c_map_rbegin
#define c_map_rend              _c_map_rend
#define c_map_empty             _c_map_empty
#define c_map_size              _c_map_size
#define c_map_max_size			_c_map_max_size
#define c_map_at                _c_map_at
#define c_map_swap              _c_map_swap
#define c_map_insert			_c_map_insert
#define c_map_insert1			_c_map_insert1
#define c_map_insert2			_c_map_insert2
#define c_map_erase             _c_map_erase
#define c_map_erase1			_c_map_erase1
#define c_map_erase2			_c_map_erase2
#define c_map_clear             _c_map_clear
#define c_map_find              _c_map_find
#define c_map_count             _c_map_count
#define c_map_lower_bound		_c_map_lower_bound
#define c_map_upper_bound		_c_map_upper_bound
#define c_map_equal_range		_c_map_equal_range
#define c_map_less              _c_map_less
#define c_map_equal             _c_map_equal


typedef struct c_map
{
	void * _l;
} c_map, * c_pmap;


void __c_map(c_pmap thiz, COMPARER keycmp);
void __c_pam(c_pmap thiz);
c_pmap c_map_assign(c_pmap thiz, const c_pmap M);
c_iterator c_map_begin(c_pmap thiz);
c_iterator c_map_end(c_pmap thiz);
c_reverse_iterator c_map_rbegin(c_pmap thiz);
c_reverse_iterator c_map_rend(c_pmap thiz);
c_bool c_map_empty(c_pmap thiz);
size_type c_map_size(c_pmap thiz);
size_type c_map_max_size(c_pmap thiz);
value_type c_map_at(c_pmap thiz, key_type key);
void c_map_swap(c_pmap thiz, c_pmap M);
c_iter_bool_pair c_map_insert(c_pmap thiz, const value_type val);
c_iterator c_map_insert1(c_pmap thiz, c_iterator position, const value_type val);
void c_map_insert2(c_pmap thiz, c_iterator first, c_iterator last);
void c_map_erase(c_pmap thiz, c_iterator position);
size_type c_map_erase1(c_pmap thiz, key_type key);
void c_map_erase2(c_pmap thiz, c_iterator first, c_iterator last);
void c_map_clear(c_pmap thiz);
c_iterator c_map_find(c_pmap thiz, key_type key);
size_type c_map_count(c_pmap thiz, key_type key);
c_iterator c_map_lower_bound(c_pmap thiz, key_type key);
c_iterator c_map_upper_bound(c_pmap thiz, key_type key);
c_iter_iter_pair c_map_equal_range(c_pmap thiz, key_type key);
c_bool c_map_less(c_pmap thiz, const c_pmap M, COMPARER paircmp);
c_bool c_map_equal(c_pmap thiz, const c_pmap M, COMPARER paircmp);


#endif /* __CF_CSTL_MAP_H_ */
