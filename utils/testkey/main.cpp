#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <string.h>
#include "..\..\armkeys.h"
#include "keys.cpp"

void main(int argc, char **argv)
{
	if(argc < 3)
	{
		printf("Usage: testkey <name> <key>");
		return;
	}

	bool is_valid = false;
	arm_keys_init();
	for(int i = 0; i < 2; i++)
	{
		if(arm_check_key(argv[1], argv[2], g_keys + i))
		{
			printf("Key is VALID.\nTemplate: %d\n", i + 1);
			is_valid = true;
			break;
		}
	}
	if(!is_valid)
	{
		printf("INVALID KEY\n");
	}
}
