﻿# ArmKeys Library

Using this library you can check the license keys generated by Software Passport key generator. This library supports ShortV3 Level 10 keys only.
Also note, currently this library does not exctract the key information, like key creatation date, keystring or extra info. This library check the ECDSA signature to make sure the key is valid.

Below is short description of the functions:

void arm_get_key(char* tpl, arm_key_data* keys);

This function generate the public key for the encryption template. Don't use this function in your main application. Import the public key into the your application to check the key. You can use the project **getkeys** to export the public key into C++ source code.

bool arm_check_key(char* name, char* key, arm_key_data* keys);

This function check the license key. It returns true if the key is valid.

void arm_keys_init();

Call this function once before calling one of the function arm_check_key or arm_get_key.