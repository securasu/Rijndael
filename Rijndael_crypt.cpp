#include "Rijndael_128.h"

using namespace securasu;

void Rijndeal_128::Crypt(CryptingMode cm) {
	byte i, j;
	byte* matrix[4];
	byte round = 0;
	for(i = 0; i < 4; ++i) {
		matrix[i] = new byte[4];
		for(j = 0; j < 4; ++j) {
			matrix[i][j] = cm == encrypt ? plaintext[j * 4 + i] : ciphertext[j * 4 + i];
		}
	}
	KeyExpansion();
	AddRoundKey(matrix, round, cm);
	while(round < 10) {
		++round;
		SubBytes(matrix, cm);
		ShiftRows(matrix, cm);
		if(round != 10)
			MixColumns(matrix, cm);
		AddRoundKey(matrix, round, cm);
	}
	for(i = 0; i < 4; ++i) {
		for(j = 0; j < 4; ++j) {
			if(cm == encrypt)
				ciphertext[j * 4 + i] = matrix[i][j];
			else
				plaintext[j * 4 + i] = matrix[i][j];
		}
		delete[] matrix[i];
	}
}