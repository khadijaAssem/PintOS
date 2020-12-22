#ifndef FIXED_POINT_H
#define FIXED_POINT_H
/* Fixed-Point constants. */
#define FIXED_P_FRAQ_BITS 14  /* 2^14 */
#define FIXED_POINT_F (1 << FIXED_P_FRAQ_BITS)

/* Fixed-Point type. */
typedef struct{
    int val
} fixed_point_t;

fixed_point_t int_to_fixed_p (int);
int fixed_p_to_int (fixed_point_t);

fixed_point_t fixed_p_multiply (fixed_point_t x, fixed_point_t y);
fixed_point_t fixed_p_divide (fixed_point_t x, fixed_point_t y);
fixed_point_t mul (fixed_point_t x, int y);
fixed_point_t div (fixed_point_t x, int y);
fixed_point_t fixed_p_add (fixed_point_t x, fixed_point_t y);
fixed_point_t fixed_p_sub (fixed_point_t x, fixed_point_t y);

int power (int base,int exponent);

#endif