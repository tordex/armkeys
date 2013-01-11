/************************************************************
*															*
*  Implement combinations of math packages to create 		*
*  advanced protocols.  Massy-Omura is first example.		*
*  Nyberg_Rueppel second.									*
*															*
*				Author = Mike Rosing						*
*				 Date  = Jan 4, 1998						*
*															*
*		NR Jan. 9, 1998										*
*															*
************************************************************/

#include "armkeys_int.h"

extern unsigned long random_seed;
extern void md5_hash(unsigned long *i, const void *bytes, unsigned long length);

/*  print out an integer.  input is label string and pointer
	to integer, sends to terminal.
*/

void print_int(char* string, BIGINT* number)
{
	char	teststring[MAXSTRING], outchar[2*MAXSTRING];
	

	bigint_to_ascii(number, teststring);
	sprintf(outchar, "%s\n%s\n", string, teststring);
	printf("%s\n", outchar);
}
	
/*  function to compare BIGINT value to 1.
	Returns 1 if it is, 0 otherwise.
*/

INDEX int_onecmp(BIGINT *number)
{
	INDEX	i;
	
	if ( number->hw[INTMAX] > 1) return (0);
	for ( i=0; i<INTMAX; i++)
		if ( number->hw[i]) return (0);
	if (number->hw[INTMAX]) return (1);
	return (0);
}

/*  Generate a key pair, a random value plus a point.
	This was called ECKGP for Elliptic Curve Key Generation
	Primitive in an early draft of IEEE P1363.

	Input:  EC parameters including public curve, point,
			point order and cofactor
	
	Output: EC key pair including
			secret key k and random point R = k* base point
*/

void ECKGP(ecc_parameter* Base, ecc_keypair* Key)
{
	BIGINT		key_num, point_order, quotient, remainder;
	FIELD2N		rand_key;
	
/*  ensure random value is less than point order  */
	
	random_field( &rand_key);
	field_to_int( &rand_key, &key_num);
	field_to_int( &Base->pnt_order, &point_order);
	int_div( &key_num, &point_order, &quotient, &remainder);
	int_to_field( &remainder, &Key->prvt_key);

	elptic_mul( &Key->prvt_key, &Base->pnt, &Key->pblc_key, &Base->crv);
}

/*  Subroutine to compute hash of a message and return the result 
	as an integer.  Used in all signature schemes.
	
	Enter with pointer to message, message length
*/

void hash_to_int( unsigned char* Message, unsigned long length, BIGINT* hash_value)
{
	unsigned long	message_digest[4];	/*  from MD5 hash function  */
	FIELD2N		 	mdtemp;			/*  convert to NUMBITS size (if needed)  */
	INDEX			i, count;
	
/*  compute hash of input message  */

	md5_hash(message_digest, Message, length);

/*  convert message digest into an integer */

	null ( &mdtemp);
	count = 0;
	SUMLOOP (i)
	{
		mdtemp.e[i] = message_digest[i];
		count++;
		if (count > 4) break;
	}
	//mdtemp.e[0] &= UPRMASK;
	field_to_int( &mdtemp, hash_value);
}

/*  DSA version of Elliptic curve signature primitive of IEEE P1363.

	Enter with EC parameters, signers private key, pointer to message and
	it's length.
	
	Output is 2 values in SIGNITURE structure.
	value "c" = x component of random point modulo point order of
				public point  (random point = random key * public point)
	value "d" = (random key)^-1 * (message hash + signer's key * c)
*/

void onb_DSA_Signature( unsigned char *Message, unsigned long length, ecc_parameter *public_curve, FIELD2N *secret_key, ecc_signature *signature)
{
	BIGINT			hash_value;		/*  then to an integer  */
	ecc_keypair		random_key;
	BIGINT			x_value, k_value, sig_value, c_value;
	BIGINT			temp, quotient;
	BIGINT			key_value, point_order, u_value;

/*  compute hash of input message  */

	hash_to_int( Message, length, &hash_value);
	
/*  create random value and generate random point on public curve  */

	ECKGP( public_curve, &random_key);
		
/*  convert x component of random point to an integer modulo
	the order of the base point.  This is first part of 
	signature.
*/

	field_to_int( &public_curve->pnt_order, &point_order);
	field_to_int( &random_key.pblc_key.x, &x_value);
	int_div( &x_value, &point_order, &quotient, &c_value);
	int_to_field( &c_value, &signature->c);
	
/*	multiply that  by signers private key and add to message
	digest modulo the order of the base point. 
	hash value + private key * c value
*/

	field_to_int( secret_key, &key_value);
	int_mul( &key_value, &c_value, &temp);
	int_add( &temp, &hash_value, &temp);
	int_div( &temp, &point_order, &quotient, &k_value);
	
/*  final step is to multiply by inverse of random key value
		modulo order of base point.
*/

	field_to_int( &random_key.prvt_key, &temp);
	mod_inv( &temp, &point_order, &u_value);
	int_mul( &u_value, &k_value, &temp);
	int_div( &temp, &point_order, &quotient, &sig_value);
	int_to_field( &sig_value, &signature->d);
}

/*  verify a signature of a message using DSA scheme.

	Inputs:	Message to be verified of given length,
			elliptic curve parameters public_curve 
			signer's public key (as a point),
			signature block.
	
	Output: value 1 if signature verifies,
			value 0 if failure to verify.
*/

int onb_DSA_Verify( unsigned char* Message, unsigned long length, ecc_parameter* public_curve, ecc_point* signer_point, ecc_signature* signature)
{
	BIGINT			hash_value;
	ecc_point			Temp1, Temp2, Verify;
	BIGINT			c_value, d_value;
	BIGINT			temp, quotient, h1, h2;
	BIGINT			check_value, point_order;
	INDEX			i;
	FIELD2N			h1_field, h2_field;

/*  compute inverse of second signature value  */

	field_to_int( &public_curve->pnt_order, &point_order);
	field_to_int( &signature->d, &temp);
	mod_inv( &temp, &point_order, &d_value);
	
/*  generate hash of message  */

	hash_to_int( Message, length, &hash_value);

/*  compute elliptic curve multipliers:
	h1 = hash value * d_value, h2 = c * d_value
*/

	int_mul( &hash_value, &d_value, &temp);
	int_div( &temp, &point_order, &quotient, &h1);
	int_to_field( &h1, &h1_field);
	field_to_int( &signature->c, &c_value);
	int_mul( &d_value, &c_value, &temp);
	int_div( &temp, &point_order, &quotient, &h2);
	int_to_field( &h2, &h2_field);

/*  find hidden point from public data  */

	elptic_mul( &h1_field, &public_curve->pnt, &Temp1, &public_curve->crv);
	elptic_mul( &h2_field, signer_point, &Temp2, &public_curve->crv);
	esum( &Temp1, &Temp2, &Verify, &public_curve->crv);
	
/*  convert x value of verify point to an integer modulo point order */

	field_to_int( &Verify.x, &temp);
	int_div( &temp, &point_order, &quotient, &check_value);
	
/*  compare resultant message digest from original signature  */

	int_null(&temp);
	int_sub( &c_value, &check_value, &temp);
	while( temp.hw[0] & 0x8000) 		/*  ensure positive zero */
		int_add( &point_order, &temp, &temp);

/*  return error if result of subtraction is not zero  */

	INTLOOP(i) if (temp.hw[i]) return(0);  
	return(1);
}
