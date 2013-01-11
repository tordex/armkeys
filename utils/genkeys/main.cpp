#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <string.h>
#include <ctype.h> 
#include "..\..\armkeys.h"

void trim_string(char* str) 
{
	int len = strlen(str);
	for(int i = len - 1; i >= 0; i--)
	{
		if(isspace((unsigned char) str[i]))
		{
			str[i] = 0;
		}
	}
};

void main(int argc, char **argv)
{
	if(argc < 2)
	{
		printf("Usage: genkeys <filename>");
		return;
	}

	FILE* fl = fopen(argv[1], "rt");
	if(!fl)
	{
		printf("Impossible to open the file: %s", argv[1]);
		return;
	}

	printf("arm_key_data g_keys[] = \n{\n");

	char comment[255];
	char tpl[255];
	while(!feof(fl))
	{
		if(fgets(comment, 255, fl))
		{
			trim_string(comment);
			if(fgets(tpl, 255, fl))
			{
				trim_string(tpl);
				if(tpl[0])
				{
					arm_key_data keys;
					arm_get_key(tpl, &keys);

					printf("\t// %s\n\t// template: %s\n", comment, tpl);
					printf("\t{\n\t\t{");

					for(int i = 0; i < 8; i++)
					{
						printf("0x%08X", keys.base_pnt[i]);
						if(i != 7)
						{
							printf(", ");
						}
					}
					printf("},\n\t\t{");
					for(int i = 0; i < 8; i++)
					{
						printf("0x%08X", keys.pub_key[i]);
						if(i != 7)
						{
							printf(", ");
						}
					}
					printf("}\n\t},\n");
				}
			}
		}
	}
	printf("};\n");
}
