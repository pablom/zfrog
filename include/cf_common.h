// cf_common.h

#ifndef __CF_COMMON_H__
#define __CF_COMMON_H__


#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

#ifdef HAVE_TYPEOF

/*
* Can use arbitrary expressions
*/
#define alignof(t) \
((sizeof (t) > 1)? offsetof(struct { char c; typeof(t) x; }, x) : 1)

#else

/*
* Can only use types
*/
#define alignof(t) \
((sizeof (t) > 1)? offsetof(struct { char c; t x; }, x) : 1)

#endif

#define	i_to_2_byte(a, i)	(((uint8_t *)(a))[0] = ((i) >> 8) & 0xFF,\
                            ((uint8_t *)(a))[1] = (i) & 0xFF)

#define	i_to_3_byte(a, i)	(((uint8_t *)(a))[0] = ((i) >> 16)& 0xFF,\
                            ((uint8_t *)(a))[1] = ((i) >> 8) & 0xFF,\
                            ((uint8_t *)(a))[2] = (i) & 0xFF)

#define	i_to_4_byte(a, i)	(((uint8_t *)(a))[0] = ((i) >> 24)& 0xFF,\
                            ((uint8_t *)(a))[1] = ((i) >> 16)& 0xFF,\
                            ((uint8_t *)(a))[2] = ((i) >> 8) & 0xFF,\
                            ((uint8_t *)(a))[3] = (i) & 0xFF)


#define	a_to_byte(a)		(((uint8_t *) a)[0])

#define	a_to_u_byte(a)		((uint8_t) \
                            (((uint8_t *) a)[0]		& 0xFF))

#define	a_to_u_2_byte(a)	((uint16_t) \
                            ((((uint8_t *) a)[1]		& 0xFF) | \
                            (((uint8_t *) a)[0] << 8	& 0xFF00)))

#define	a_to_2_byte(a)		(int)(int16_t)a_to_u_2_byte(a)

#define	a_to_u_3_byte(a)	((uint32_t) \
                            ((((uint8_t *) a)[2]		& 0xFF) | \
                            (((uint8_t *) a)[1] << 8	& 0xFF00) | \
                            (((uint8_t *) a)[0] << 16	& 0xFF0000)))


#ifdef	__STDC__
#	define	__TOP_4BYTE	0xFF000000UL
#else
#	define	__TOP_4BYTE	0xFF000000
#endif

#define	a_to_u_4_byte(a)	((uint32_t) \
                            ((((uint8_t*) a)[3]		& 0xFF) | \
                            (((uint8_t*) a)[2] << 8	& 0xFF00) | \
                            (((uint8_t*) a)[1] << 16	& 0xFF0000) | \
                            (((uint8_t*) a)[0] << 24	& __TOP_4BYTE)))

#define	a_to_4_byte(a)		(long)(int32_t)a_to_u_4_byte(a)

/*
 * Little Endian versions of above macros
 */
#define	li_to_2_byte(a, i)	(((uint8_t *)(a))[1] = ((i) >> 8) & 0xFF,\
                            ((uint8_t *)(a))[0] = (i) & 0xFF)

#define	li_to_3_byte(a, i)	(((uint8_t *)(a))[2] = ((i) >> 16)& 0xFF,\
                            ((uint8_t *)(a))[1] = ((i) >> 8) & 0xFF,\
                            ((uint8_t *)(a))[0] = (i) & 0xFF)

#define	li_to_4_byte(a, i)	(((uint8_t *)(a))[3] = ((i) >> 24)& 0xFF,\
                            ((uint8_t *)(a))[2] = ((i) >> 16)& 0xFF,\
                            ((uint8_t *)(a))[1] = ((i) >> 8) & 0xFF,\
                            ((uint8_t *)(a))[0] = (i) & 0xFF)


#define	la_to_u_2_byte(a)	((uint16_t) \
                            ((((uint8_t*) a)[0]		& 0xFF) | \
                            (((uint8_t*) a)[1] << 8	& 0xFF00)))

#define	la_to_2_byte(a)		(int)(int16_t)la_to_u_2_byte(a)

#define	la_to_u_3_byte(a)	((uint32_t) \
                            ((((uint8_t*) a)[0]		& 0xFF) | \
                            (((uint8_t*) a)[1] << 8	& 0xFF00) | \
                            (((uint8_t*) a)[2] << 16	& 0xFF0000)))

#define	la_to_3_byte(a)		la_to_u_3_byte(a)	/* XXX Is there a signed version ? */

#define	la_to_u_4_byte(a)	((uint32_t) \
                            ((((uint8_t*) a)[0]		& 0xFF) | \
                            (((uint8_t*) a)[1] << 8	& 0xFF00) | \
                            (((uint8_t*) a)[2] << 16	& 0xFF0000) | \
                            (((uint8_t*) a)[3] << 24	& __TOP_4BYTE)))

#define	la_to_4_byte(a)		(long)(int32_t)la_to_u_4_byte(a)


#endif /* __CF_COMMON_H__ */
