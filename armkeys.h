#pragma once

struct arm_key_data
{
	unsigned int	base_pnt[8];
	unsigned int	pub_key[8];
};

void arm_get_key(char* tpl, arm_key_data* keys);
bool arm_check_key(char* name, char* key, arm_key_data* keys);
void arm_keys_init();
void md5_hash(unsigned long* hash, const void* bytes, unsigned long length);
