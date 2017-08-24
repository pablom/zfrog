// cf_cstl_pair.h
 
#include "cf_cstl_pair.h"


c_pair c_make_pair(const value_type x, const value_type y)
{
	c_pair tmp;
	tmp.first = x;
	tmp.second = y;
	return tmp;
}

c_iter_bool_pair c_make_iter_bool_pair(c_iterator x, c_bool y)
{
	c_iter_bool_pair tmp;
	tmp.first = x;
	tmp.second = y;
	return tmp;
}

c_iter_iter_pair c_make_iter_iter_pair(c_iterator x, c_iterator y)
{
	c_iter_iter_pair tmp;
	tmp.first = x;
	tmp.second = y;
	return tmp;
}
