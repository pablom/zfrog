// cf_cstl_pair.h

#ifndef __CF_CSTL_PAIR_H
#define __CF_CSTL_PAIR_H

#include "cf_cstl_iterator.h"
#include "cf_cstl_memory.h"

#define c_pair                  _c_pair
#define c_ppair                 _c_ppair
#define c_iter_bool_pair        _c_iter_bool_pair
#define c_piter_bool_pair       _c_piter_bool_pair
#define c_iter_iter_pair        _c_iter_iter_pair
#define c_piter_iter_pair       _c_piter_iter_pair
#define c_make_pair             _c_make_pair
#define c_make_iter_bool_pair	_c_make_iter_bool_pair
#define c_make_iter_iter_pair	_c_make_iter_iter_pair

typedef value_type first_type;
typedef value_type second_type;

typedef struct c_pair c_pair, * c_ppair;
typedef int (*PAIR_COMPARER)(c_ppair, c_ppair);

struct c_pair
{    
	first_type first;
	second_type second;
};

typedef struct c_iter_bool_pair c_iter_bool_pair, c_piter_bool_pair;

struct c_iter_bool_pair
{
	c_iterator first;
	c_bool second;
};

typedef struct c_iter_iter_pair c_iter_iter_pair, c_piter_iter_pair;

struct c_iter_iter_pair
{
	c_iterator first;
	c_iterator second;
};


c_pair c_make_pair(const value_type x, const value_type y);
c_iter_bool_pair c_make_iter_bool_pair(c_iterator x, c_bool y);
c_iter_iter_pair c_make_iter_iter_pair(c_iterator x, c_iterator y);


#endif /* __CF_CSTL_PAIR_H */





