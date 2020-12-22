#include "threads/fixed-point.h"
#include <stdint.h>

fixed_point_t int_to_fixed_p (int n){
	fixed_point_t result;
	result.val=n*FIXED_POINT_F;
	return result;
}

int fixed_p_to_int (fixed_point_t x){
	return x.val / FIXED_POINT_F;
}

fixed_point_t mul (fixed_point_t x, int y){
	fixed_point_t result;
	result.val=((int64_t) x.val) * y ;
	return result;
}
fixed_point_t div (fixed_point_t x, int y){
	fixed_point_t result;
	result.val=((int64_t) x.val) / y ;
	return result;
}
fixed_point_t fixed_p_multiply (fixed_point_t x, fixed_point_t y){
	fixed_point_t result;
	result.val=((int64_t) x.val) * y.val / FIXED_POINT_F;
	return result;
}

fixed_point_t fixed_p_divide (fixed_point_t x, fixed_point_t y){
	fixed_point_t result;
	result.val=((int64_t) x.val) *  FIXED_POINT_F/y.val;
	return result;
}

fixed_point_t fixed_p_add (fixed_point_t x, fixed_point_t y){
	fixed_point_t result;
	result.val=x.val+y.val;
	return result;
}

fixed_point_t fixed_p_sub (fixed_point_t x, fixed_point_t y){
	fixed_point_t result;
	result.val=x.val-y.val;
	return result;
}