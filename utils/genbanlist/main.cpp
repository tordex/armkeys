#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <string.h>
#include "..\..\armkeys.h"

void prepare_key_for_hash(char *target, const char *source) 
{
	const char *s = source;
	char *t = target;
	while (*s) 
	{
		if(*s == '|') break;
		if (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') ++s;
		else if (*s >= 'a' && *s <= 'z') *t++ = ((*s++) - 'a'  +'A');
		else *t++ = *s++;
	};
	*t = 0;
};


void main(int argc, char **argv)
{
	if(argc < 2)
	{
		printf("Usage: genbanlist <filename>");
		return;
	}

	FILE* fl = fopen(argv[1], "rt");
	if(!fl)
	{
		printf("Impossible to open the file: %s", argv[1]);
		return;
	}

	printf("md5_hash_t g_banlist[] = \n{\n");

	char str[255];
	char key[255];
	while(!feof(fl))
	{
		if(fgets(str, 255, fl))
		{
			if(str[0])
			{
				prepare_key_for_hash(key, str);
				if(key[0])
				{
					unsigned long hash[4];
					md5_hash(hash, key, strlen(key));

					printf("\t{");

					for(int i = 0; i < 4; i++)
					{
						printf("0x%08X", hash[i]);
						if(i != 3)
						{
							printf(", ");
						}
					}
					printf("\t},\n");
				}
			}
		}
	}
	printf("\t{0, 0, 0, 0}\n");

	printf("};\n");
}
