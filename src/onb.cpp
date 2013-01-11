/************************************************************************************
*																					*
*		Alex project routines for generalized and variable length ONB mathematics.	*
*	copied from original source and modified with new math.  Must be optimized for	*
*	specific platforms later.  Specific implementations should remove C constructs	*
*   in favor of assembler for more speed.											*
*																					*
*									Author = mike rosing							*
*									 date  = June 7, 1997							*
************************************************************************************/

#include "armkeys_int.h"

INDEX	Lambda[2][field_prime];
INDEX	lg2_m;

void rot_left(FIELD2N *a)
{
        INDEX i;
        ELEMENT bit,temp;

        bit = (a->e[0] & UPRBIT) ? 1L : 0L;
        for (i=NUMWORD; i>=0; i--) {
           temp = (a->e[i] & MSB) ? 1L : 0L;
           a->e[i] = ( a->e[i] << 1) | bit;
           bit = temp;
        }
        a->e[0] &= UPRMASK;
}

void rot_right(FIELD2N *a)
{
        INDEX i;
        ELEMENT bit,temp;

        bit = (a->e[NUMWORD] & 1) ? UPRBIT : 0L;
        SUMLOOP(i) {
           temp = ( a->e[i] >> 1)  | bit;
           bit = (a->e[i] & 1) ? MSB : 0L;
           a->e[i] = temp;
        }
        a->e[0] &= UPRMASK;
}

void null(FIELD2N *a)
{
        INDEX i;

        SUMLOOP(i)  a->e[i] = 0;
}

void copy (FIELD2N *a, FIELD2N *b)
{
        INDEX i;

        SUMLOOP(i)  b->e[i] = a->e[i];
}

/*  binary search for most significant bit within word */

INDEX log_2(ELEMENT x)
{
	INDEX	k, lg2;
	ELEMENT ebit, bitsave, bitmask;

	lg2 = 0;
	bitsave = x;				/* grab bits we're interested in.  */
	k = WORDSIZE/2;					/* first see if msb is in top half  */
	bitmask = -1L<<k;				/* of all bits  */
	while (k)
	{
		ebit = bitsave & bitmask;	/* did we hit a bit?  */
		if (ebit)					/* yes  */
		{
			lg2 += k;				/* increment degree by minimum possible offset  */
			bitsave = ebit;			/* and zero out non useful bits  */
		}
		k /= 2;
		bitmask ^= (bitmask >> k);
	}
	return( lg2);
}

/* create Lambda [i,j] table.  indexed by j, each entry contains the
value of i which satisfies 2^i + 2^j = 1 || 0 mod field_prime.  There are
two 16 bit entries per index j except for zero.  See references for
details.  Since 2^0 = 1 and 2^2n = 1, 2^n = -1 and the first entry would
be 2^0 + 2^n = 0.  Multiplying both sides by 2, it stays congruent to
zero.  So Half the table is unnecessary since multiplying exponents by
2 is the same as squaring is the same as rotation once.  Lambda[0] stores
n = (field_prime - 1)/2.  The terms congruent to one must be found via
lookup in the log table.  Since every entry for (i,j) also generates an
entry for (j,i), the whole 1D table can be built quickly.
*/

void genlambda()
{
        INDEX i, logof, n, index;
        INDEX log2[field_prime], twoexp;

        for (i=0; i<field_prime; i++) log2[i] = -1;

/*  build antilog table first  */

        twoexp = 1;
        for (i=0; i<field_prime; i++) 
        {
          log2[twoexp] = i;
          twoexp = (twoexp << 1) % field_prime;
        }

/*  compute n for easy reference */

        n = (field_prime - 1)/2;
        
/*  fill in first vector with indicies shifted by half table size  */

        Lambda[0][0] = n;
        for (i=1; i<field_prime; i++) 
        	Lambda[0][i] = (Lambda[0][i-1] + 1) % NUMBITS;

/*  initialize second vector with known values  */
        
        Lambda[1][0]= -1;		/*  never used  */
        Lambda[1][1] = n;
        Lambda[1][n] = 1;

/*  loop over result space.  Since we want 2^i + 2^j = 1 mod field_prime
        it's a ton easier to loop on 2^i and look up i then solve the silly
        equations.  Think about it, make a table, and it'll be obvious.  */

        for (i=2; i<=n; i++) {
          index = log2[i];
          logof = log2[field_prime - i + 1];
          Lambda[1][index] = logof;
          Lambda[1][logof] = index;
        }
/*  last term, it's the only one which equals itself.  See references.  */

        Lambda[1][log2[n+1]] = log2[n+1];

/*  find most significant bit of NUMBITS.  This is int(log_2(NUMBITS)).  
	Used in opt_inv to count number of bits.  */

	lg2_m = log_2((ELEMENT)(NUMBITS - 1));
	
}

/*  Type 2 ONB initialization.  Fills 2D Lambda matrix.  */

void genlambda2()
{
	INDEX	i, logof[4], n, j, k;
	INDEX	log2[field_prime], twoexp;

/*  build log table first.  For the case where 2 generates the quadradic
	residues instead of the field, duplicate all the entries to ensure 
	positive and negative matches in the lookup table (that is, -k mod
	field_prime is congruent to entry field_prime + k).  */

	twoexp = 1;
	for (i=0; i<NUMBITS; i++)
	{
		log2[twoexp] = i;
		twoexp = (twoexp << 1) % field_prime;
	}
	if (twoexp == 1)		/*  if so, then deal with quadradic residues */
	{
		twoexp = 2*NUMBITS;
		for (i=0; i<NUMBITS; i++)
		{
			log2[twoexp] = i;
			twoexp = (twoexp << 1) % field_prime;
		}
	}
	else
	{
		for (i=NUMBITS; i<field_prime-1; i++)
		{
			log2[twoexp] = i;
			twoexp = (twoexp << 1) % field_prime;
		}
	}
		
/*  first element in vector 1 always = 1  */

	Lambda[0][0] = 1;
	Lambda[1][0] = -1;

/*  again compute n = (field_prime - 1)/2 but this time we use it to see if
	an equation applies  */
	
	n = (field_prime - 1)/2;

/*  as in genlambda for Type I we can loop over 2^index and look up index 
	from the log table previously built.  But we have to work with 4 
	equations instead of one and only two of those are useful.  Look up 
	all four solutions and put them into an array.  Use two counters, one
	called j to step thru the 4 solutions and the other called k to track
	the two valid ones.
	
	For the case when 2 generates quadradic residues only 2 equations are
	really needed.  But the same math works due to the way we filled the
	log2 table.
*/

	twoexp = 1;	
	for (i=1; i<n; i++)
	{
		twoexp = (twoexp<<1) % field_prime;
		logof[0] = log2[field_prime + 1 - twoexp];
		logof[1] = log2[field_prime - 1 - twoexp];
		logof[2] = log2[twoexp - 1];
		logof[3] = log2[twoexp + 1];
		k = 0;
		j = 0;
		while (k<2)
		{
			if (logof[j] < n)
			{
				Lambda[k][i] = logof[j];
				k++;
			}
			j++;
		}
	}

/*  find most significant bit of NUMBITS.  This is int(log_2(NUMBITS)).  
	Used in opt_inv to count number of bits.  */

	lg2_m = log_2((ELEMENT)(NUMBITS - 1));
}

/*  Generalized Optimal Normal Basis multiply.  Assumes two dimensional Lambda vector
	already initialized.  Will work for both type 1 and type 2 ONB.  Enter with pointers
	to FIELD2N a, b and result area c.  Returns with c = a*b over GF(2^NUMBITS).
*/

void opt_mul(FIELD2N *a, FIELD2N *b, FIELD2N *c)
{
	INDEX i, j;
	INDEX 	zero_index, one_index;
	FIELD2N	amatrix[NUMBITS], copyb;
	
/*  clear result and copy b to protect original  */

	null(c);
	copy(b, &copyb);

/*  To perform the multiply we need two rotations of the input a.  Performing all
	the rotations once and then using the Lambda vector as an index into a table
	makes the multiply almost twice as fast.
*/

	copy( a, &amatrix[0]);
	for (i = 1; i < NUMBITS; i++)
	{
		copy( &amatrix[i-1], &amatrix[i]);
		rot_right( &amatrix[i]);
	}

/*  Lambda[1][0] is non existant, deal with Lambda[0][0] as speical case.  */

	zero_index = Lambda[0][0];
	SUMLOOP (i) c->e[i] = copyb.e[i] & amatrix[zero_index].e[i];

/*  main loop has two lookups for every position.  */

	for (j = 1; j<NUMBITS; j++)
	{
		rot_right( &copyb);
		zero_index = Lambda[0][j];
		one_index = Lambda[1][j];
		SUMLOOP (i) c->e[i] ^= copyb.e[i] &
					(amatrix[zero_index].e[i] ^ amatrix[one_index].e[i]);
	}
}

/*  Generic ONB inversion routine.
	Input is pointer to ONB number.
	Output is inverse of input, overwrites input in place.
*/

void opt_inv(FIELD2N *a, FIELD2N *result)
{
	FIELD2N	shift, temp;
	INDEX	m, s, r, rsft;
	
/*  initialize s to lg2_m computed in genlambda.  Since msb is always set,
	initialize result to input a and skip first math loop.
*/

	s = lg2_m - 1;
	copy( a, result);
	m = NUMBITS - 1;

/*  create window over m and walk up chain of terms  */

	while (s >= 0)
	{
		r = m >> s;
		copy( result, &shift);
		for (rsft = 0; rsft < (r>>1); rsft++) rot_left( &shift);
		opt_mul( result, &shift, &temp);
		if ( r&1 )			/* if window value odd  */
		{
			rot_left( &temp);	/*  do extra square  */
			opt_mul( &temp, a, result);	/*  and multiply  */
		}
		else copy( &temp, result);
		s--;
	}
	rot_left(result);		/* final squaring  */
}
