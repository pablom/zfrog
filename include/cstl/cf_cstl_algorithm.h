// cf_cstl_algorithm.h

#ifndef __CF_CSTL_ALGORITHM_H_
#define __CF_CSTL_ALGORITHM_H_

#include "cf_cstl_iterator.h"
#include "cf_cstl_function.h"

#define c_iter_swap                 _c_iter_swap
#define c_copy                      _c_copy
#define c_copy_backward             _c_copy_backward
#define c_lexicographical_compare   _c_lexicographical_compare
#define c_uninitialized_copy        _c_uninitialized_copy
#define c_fill                      _c_fill
#define c_fill_n                    _c_fill_n
#define c_uninitialized_fill_n      _c_unintialized_fill_n
#define c_equal                     _c_equal
#define c_equal2                    _c_equal2
#define c_for_each                  _c_for_each
#define c_find                      _c_find
#define c_find_if                   _c_find_if
#define c_adjacent_find             _c_adjacent_find
#define c_count                     _c_count
#define c_count_if                  _c_count_if
#define c_reverse                   _c_reverse
#define c_search                    _c_search

void c_iter_swap(c_iterator x, c_iterator y);
c_iterator c_copy(c_iterator first, c_iterator last, c_iterator result);
c_iterator c_copy_backward(c_iterator first, c_iterator last, c_iterator result);
c_bool c_lexicographical_compare(c_iterator first1, 
                                    c_iterator last1, 
                                    c_iterator first2, 
                                    c_iterator last2,
                                    COMPARER cmp);
c_iterator c_uninitialized_copy(c_iterator first, c_iterator last, c_iterator result);
void c_fill(c_iterator first, c_iterator last, const value_type val);
c_iterator c_fill_n(c_iterator first, size_type n, const value_type val);
c_iterator c_uninitialized_fill_n(c_iterator first, size_type n, const value_type val);
c_bool c_equal(c_iterator first1, c_iterator last1, c_iterator first2, BINARY_PREDICATE pf);
c_bool c_equal2(c_iterator first1, c_iterator last1, c_iterator first2, c_binary_predicate binary_pred);
UNARY_FUNCTION c_for_each(c_iterator first, c_iterator last, UNARY_FUNCTION pf);
c_iterator c_find(c_iterator first, c_iterator last, const value_type val);
c_iterator c_find_if(c_iterator first, c_iterator last, UNARY_PREDICATE pf);
c_iterator c_adjacent_find(c_iterator first, c_iterator last, BINARY_PREDICATE pf);
size_type c_count(c_iterator first, c_iterator last, const value_type val);
size_type c_count_if(c_iterator first, c_iterator last, UNARY_PREDICATE pf);
void c_reverse(c_iterator first, c_iterator last);
c_iterator c_search(c_iterator first1, 
			c_iterator last1, 
			c_iterator first2, 
			c_iterator last2,
			BINARY_PREDICATE pf);


#define C_SWAP(X, Y, TMP)   do{(TMP)=(X);(X)=(Y);(Y)=(TMP);}while(0)
#define C_MAX(X, Y) ((X) >= (Y) ? (X) : (Y))
#define C_MIN(X, Y) ((X) <= (Y) ? (X) : (Y))

#endif /* __CF_CSTL_ALGORITHM_H_ */
