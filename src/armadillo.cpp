#include "armkeys_int.h"
#include "..\armkeys.h"

void cook_text(char *target, const char *source) 
{
	const char *s = source;
	char *t = target;
	while (*s) 
	{
		if (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') ++s;
		else if (*s >= 'a' && *s <= 'z') *t++ = ((*s++) - 'a'  +'A');
		else *t++ = *s++;
	};
	*t = 0;
};

unsigned long arm_mult(long p, long q) 
{
	unsigned long p1 = p / 10000L;
	unsigned long p0 = p % 10000L;
	unsigned long q1 = q / 10000L;
	unsigned long q0 = q % 10000L;
	return (((p0 * q1 + p1 * q0) % 10000L) * 10000L + p0 * q0) % 100000000L;
};

unsigned long arm_rand_range( long range, unsigned long& seed)
{
	seed = (arm_mult(seed, 31415821L) + 1) % 100000000L;
	return (((seed / 10000L) * range) / 10000L);
}

unsigned long arm_rand_num( unsigned long& seed)
{
	long n1 = arm_rand_range(256, seed);
	long n2 = arm_rand_range(256, seed);
	long n3 = arm_rand_range(256, seed);
	long n4 = arm_rand_range(256, seed);
	return (n1 << 24) | (n2 << 16) | (n3 << 8) | n4;
}


void arm_ECKGP(ecc_parameter* Base, ecc_keypair* Key, BIGINT* key_num)
{
	BIGINT		point_order, quotient, remainder;

	/*  ensure random value is less than point order  */

	field_to_int( &Base->pnt_order, &point_order);
	int_div( key_num, &point_order, &quotient, &remainder);
	int_to_field( &remainder, &Key->prvt_key);

	elptic_mul( &Key->prvt_key, &Base->pnt, &Key->pblc_key, &Base->crv);
}


void make_parameters(char* arm_template, ecc_parameter* Base, ecc_keypair* Key)
{
	char			encryption_template[512];
	unsigned long	md5[4];
	unsigned long	basepointinit;
	char			string1[MAXSTRING] = "5192296858534827627896703833467507"; /*N 113  */
	BIGINT			prime_order;

	Base->crv.form = 1;
	one(&Base->crv.a2);
	one(&Base->crv.a6);

	ascii_to_bigint(string1, &prime_order);
	int_to_field( &prime_order, &Base->pnt_order);
	null( &Base->cofactor);
	Base->cofactor.e[NUMWORD] = 2;

	cook_text(encryption_template, arm_template);
	md5_hash(md5, encryption_template, strlen(encryption_template));
	basepointinit = md5[0];

	INDEX	i;
	FIELD2N	rf;
	ecc_point	rnd_point;

	SUMLOOP(i) rf.e[i] = arm_rand_num(basepointinit);
	rf.e[0] &= UPRMASK;

	opt_embed( &rf, &Base->crv, NUMWORD, rf.e[NUMWORD] & 1, &rnd_point);
	edbl( &rnd_point, &Base->pnt, &Base->crv);

	char rndinitstring[1024];
	strcpy(rndinitstring, encryption_template);
	strcat(rndinitstring, "PVTKEY");

	BIGINT secretkeyhash;
	hash_to_int((unsigned char*) rndinitstring, strlen(rndinitstring), &secretkeyhash);

	arm_ECKGP(Base, Key, &secretkeyhash);
};

void decode_key_block(unsigned char* in_bytes, unsigned char* out_bytes)
{
	unsigned __int64 buffer = 0;
	for(int i = 0; i < 8; i++)
	{
		unsigned __int64 val = in_bytes[i];
		val <<= i * 5;
		buffer = buffer | val;
	}

	for(int i = 4; i >= 0; i--)
	{
		out_bytes[i] = (unsigned char) (buffer >> (i * 8));
	}
}

int decode_key_bytes(char* key, unsigned char* bytes)
{
	char rev_key[255];
	strcpy(rev_key, key);
	_strrev(rev_key);

	// cut off the key
	int key_len = strlen(rev_key);
	for(int i = key_len - 1; i >= 0; i--)
	{
		if(rev_key[i] == '1')
		{
			rev_key[i] = 0;
			break;
		}
	}

	char* shortv3digits="0123456789ABCDEFGHJKMNPQRTUVWXYZ";

	// map digits
	unsigned char mapped_key[255];
	int mapped_key_len = 0;
	for(int i = 0; rev_key[i]; i++)
	{
		for(int j = 0; shortv3digits[j]; j++)
		{
			if(rev_key[i] == shortv3digits[j])
			{
				mapped_key[mapped_key_len++] = (unsigned char) j;
				break;
			}
		}
	}

	int d = mapped_key_len / 8;
	int r = mapped_key_len % 8;

	int out_len = 0;

	for(int i = 0; i < d; i++)
	{
		decode_key_block(mapped_key + i * 8, bytes + out_len);
		out_len += 5;
	}

	if(r)
	{
		unsigned char padd[8];
		memset(padd, 0, sizeof(padd));
		for(int i = 0; i < r; i++)
		{
			padd[i] = mapped_key[mapped_key_len - r + i];
		}
		decode_key_block(padd, bytes + out_len);
		out_len += (r * 5) / 8;
		if((r * 5) % 8)
		{
			out_len++;
		}
	}
	return out_len;
}

int arm_check_key(char* name, char* key, ecc_parameter* Base, ecc_point* public_key)
{
	unsigned char decoded_key[512];
	memset(decoded_key, 0, sizeof(decoded_key));
	int decoded_key_len = decode_key_bytes(key, decoded_key);

	ecc_signature sig;
	int idx = 0;
	for(int i = 0; i < 4; i++)
	{
		if(idx >= decoded_key_len) break;
		sig.c.e[i] = 0;
		int cnt = i == 0 ? 1 : 3;
		for(int j = cnt; j >= 0; j--)
		{
			if(idx >= decoded_key_len) break;
			sig.c.e[i] |= decoded_key[idx] << (j * 8);
			idx++;
		}
	}

	for(int i = 0; i < 4; i++)
	{
		if(idx >= decoded_key_len) break;
		sig.d.e[i] = 0;
		int cnt = i == 0 ? 1 : 3;
		for(int j = cnt; j >= 0; j--)
		{
			if(idx >= decoded_key_len) break;
			sig.d.e[i] |= decoded_key[idx] << (j * 8);
			idx++;
		}
	}

	unsigned char key_bytes[512];
	int key_bytes_len = decoded_key_len - 29;

	if(key_bytes_len <= 0)
	{
		return 0;
	}

	for(int i = 0; i < key_bytes_len; i++)
	{
		key_bytes[key_bytes_len - i - 1] = decoded_key[idx];
		idx++;
	}


	char cooked_name[255];
	cook_text(cooked_name, name);
	memcpy(key_bytes + key_bytes_len, cooked_name, strlen(cooked_name));

	if(onb_DSA_Verify( key_bytes, key_bytes_len + strlen(cooked_name), Base, public_key, &sig))
	{
		return 1;
	}

	return 0;
}

void arm_get_key(char* tpl, arm_key_data* keys)
{
	ecc_parameter	Base;
	ecc_keypair		Signer;

	genlambda2();
	//random_seed = 0xFACED0FF;
	make_parameters(tpl, &Base, &Signer);

	memcpy(keys->base_pnt, &Base.pnt, sizeof(keys->base_pnt));
	memcpy(keys->pub_key, &Signer.pblc_key, sizeof(keys->pub_key));
}

bool arm_check_key(char* name, char* key, arm_key_data* keys)
{
	ecc_parameter	Base;
	ecc_keypair		Signer;
	char			string1[MAXSTRING] = "5192296858534827627896703833467507"; /*N 113  */
	BIGINT			prime_order;

	Base.crv.form = 1;
	one(&Base.crv.a2);
	one(&Base.crv.a6);

	ascii_to_bigint(string1, &prime_order);
	int_to_field( &prime_order, &Base.pnt_order);
	null( &Base.cofactor);
	Base.cofactor.e[NUMWORD] = 2;

	memcpy(&Base.pnt, keys->base_pnt, sizeof(keys->base_pnt));
	memcpy(&Signer.pblc_key, keys->pub_key, sizeof(keys->pub_key));

	if(arm_check_key(name, key, &Base, &Signer.pblc_key))
	{
		return true;
	}
	return false;
}

void arm_keys_init()
{
	genlambda2();
}
