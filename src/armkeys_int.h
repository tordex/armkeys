#pragma once

#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <memory>

#pragma pack(push)
#pragma pack(1)

#define WORDSIZE	(sizeof(int) * 8)
#define NUMBITS		113
#define TYPE2
/*#undef TYPE2 */

#ifdef TYPE2
#define field_prime	((NUMBITS << 1) + 1)
#else
#define field_prime (NUMBITS+1)
#endif

#define	NUMWORD		(NUMBITS / WORDSIZE)
#define UPRSHIFT	(NUMBITS % WORDSIZE)
#define MAX_LONG		(NUMWORD + 1)

#define MAXBITS		(MAX_LONG * WORDSIZE)
#define MAXSHIFT	(WORDSIZE - 1)
#define MSB			(1L << MAXSHIFT)

#define UPRBIT		(1L << (UPRSHIFT - 1))
#define UPRMASK		(~(-1L << UPRSHIFT))
#define SUMLOOP(i)	for(i=0; i<MAX_LONG; i++)

typedef	short int INDEX;

typedef unsigned long ELEMENT;

typedef struct 
{
	ELEMENT 	e[MAX_LONG];
}  FIELD2N;

typedef struct 
{
	INDEX   form;
	FIELD2N  a2;
	FIELD2N  a6;
} ecc_curve;

/*  coordinates for a point  */

typedef struct 
{
	FIELD2N  x;
	FIELD2N  y;
} ecc_point;


/*  These structures described in IEEE P1363 Nov. 1997  */

typedef struct
{
	ecc_curve	crv;
	ecc_point	pnt;
	FIELD2N	pnt_order;
	FIELD2N	cofactor;
} ecc_parameter;

typedef struct
{
	FIELD2N	prvt_key;
	ecc_point	pblc_key;
} ecc_keypair;

typedef struct 
{
	FIELD2N		c;
	FIELD2N		d;
} ecc_signature;


#define	HALFSIZE	(WORDSIZE/2)
#define	HIMASK		(-1L<<HALFSIZE)
#define LOMASK		(~HIMASK)
#define CARRY		(1L<<HALFSIZE)
#define MSB_HW		(CARRY>>1)
#define	INTMAX		(4*MAX_LONG-1)
#define MAXSTRING	(MAX_LONG*WORDSIZE/3)

#define	INTLOOP(i)	for(i=INTMAX;i>=0;i--)

typedef struct 
{
	ELEMENT		hw[4*MAX_LONG];
}  BIGINT;


//////////////////////////////////////////////////////////////////////////

void int_null(BIGINT* a);
void int_copy(BIGINT* a, BIGINT*b);
void field_to_int( FIELD2N *a ,BIGINT *b);
void int_to_field( BIGINT *a, FIELD2N *b);
void int_neg(BIGINT *a);
void int_add(BIGINT *a, BIGINT *b, BIGINT *c);
void int_sub(BIGINT *a, BIGINT *b, BIGINT *c);
void int_mul(BIGINT *a, BIGINT *b, BIGINT *c);
void int_div(BIGINT *top, BIGINT *bottom, BIGINT *quotient, BIGINT *remainder);
void ascii_to_bigint(char *instring, BIGINT *outhex);
void bigint_to_ascii( BIGINT *inhex, char *outstring);
void int_gcd(BIGINT *u, BIGINT *v, BIGINT *w);
void mod_exp(BIGINT *x, BIGINT *n, BIGINT *q, BIGINT *z);
void mod_inv(BIGINT *a, BIGINT *b, BIGINT *x);
void int_div2(BIGINT *x);

//////////////////////////////////////////////////////////////////////////

void	make_parameters(char* arm_template, ecc_parameter* Base, ecc_keypair* Key);
int		arm_check_key(char* name, char* key, ecc_parameter* Base, ecc_point* public_key);
void	print_int(char* string, BIGINT* number);
INDEX	int_onecmp(BIGINT *number);
void	onb_DSA_Signature( unsigned char *Message, unsigned long length, ecc_parameter *public_curve, FIELD2N *secret_key, ecc_signature *signature);
int		onb_DSA_Verify( unsigned char* Message, unsigned long length, ecc_parameter* public_curve, ecc_point* signer_point, ecc_signature* signature);
void	hash_to_int( unsigned char* Message, unsigned long length, BIGINT* hash_value);
void	md5_hash(unsigned long *i, const void *bytes, unsigned long length);

/****************************************************************
*                                                               *
*       These are structures used to create elliptic curve      *
*  points and parameters.  "form" is a just a fast way to check *
*  if a2 == 0.                                                  *
*               form            equation                        *
*                                                               *
*                0              y^2 + xy = x^3 + a_6            *
*                1              y^2 + xy = x^3 + a_2*x^2 + a_6  *
*                                                               *
****************************************************************/

/* elliptic curves functions prototypes */

void	rot_left(FIELD2N *a);
void	rot_right(FIELD2N *a);
void	null(FIELD2N *a);
void	copy (FIELD2N *a, FIELD2N *b);
void	genlambda();
void	genlambda2();
void	opt_mul(FIELD2N *a, FIELD2N *b, FIELD2N *c);
void	opt_inv(FIELD2N *a, FIELD2N *result);
INDEX	log_2(ELEMENT x);
int		opt_quadratic(FIELD2N *a, FIELD2N *b, FIELD2N *y);
void	fofx(FIELD2N *x, ecc_curve *curv, FIELD2N *f);
void	esum (ecc_point *p1, ecc_point *p2, ecc_point *p3, ecc_curve *curv);
void	edbl (ecc_point *p1, ecc_point *p3, ecc_curve *curv);
void	esub (ecc_point *p1, ecc_point *p2, ecc_point *p3, ecc_curve *curv);
void	copy_point (ecc_point *p1, ecc_point *p2);
void	elptic_mul(FIELD2N *k, ecc_point *p, ecc_point *r, ecc_curve *curv);
void	one(FIELD2N*);
void	random_field(FIELD2N* value);
void	Mother(unsigned long *pSeed);
void	opt_embed( FIELD2N	*data, ecc_curve* curv, INDEX incrmt, INDEX root, ecc_point* pnt);
void	ECKGP(ecc_parameter* Base, ecc_keypair* Key);
void	rand_curve (ecc_curve *curv);
void	rand_point( ecc_point* point, ecc_curve *curve);
void	print_field( char *string, FIELD2N *field);
void	print_point( char *string, ecc_point *point);
void	print_curve( char *string, ecc_curve *curv);

#pragma pack(pop)
