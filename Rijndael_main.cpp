#include <iostream>
#include "Rijndael_128.h"

using namespace securasu;
using namespace std;

int main() {
	Rijndeal_128 aes;
	byte plain[0x10] = {
		0x01, 0x23, 0x45, 0x67,
		0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98,
		0x76, 0x54, 0x32, 0x10
	};
	byte key[0x10] = {
		0x0f, 0x15, 0x71, 0xc9,
		0x47, 0xd9, 0xe8, 0x59,
		0x0c, 0xb7, 0xad, 0xd6,
		0xaf, 0x7f, 0x67, 0x98
	};
	int i;
	byte *pp, *cp;
	pp = aes.getPlainText();
	cp = aes.getCipherText();
	aes.setPlainText(plain);
	aes.setKey(key);
	aes.Crypt(encrypt);
	for(i = 0; i < 0x10; ++i) {
		cout << hex << (short)pp[i] << ' ';
	}
	cout << endl;
	for(i = 0; i < 0x10; ++i) {
		cout << hex << (short)cp[i] << ' ';
	}
	cout << endl;
	aes.Crypt(decrypt);
	for(i = 0; i < 0x10; ++i) {
		cout << hex << (short)pp[i] << ' ';
	}
	cout << endl;
	return 0;
}