#include "Rijndael_128.h"

using namespace securasu;

void Rijndeal_128::SubBytes(byte * matrix[], CryptingMode cm) {
	byte i, j;
	for(i = 0; i < 0x04; ++i) {
		for(j = 0; j < 0x04; ++j) {
			matrix[i][j] = cm == encrypt ? S_BOX[matrix[i][j] >> 4][matrix[i][j] & 0x0f] : 
				S_BOX_INV[matrix[i][j] >> 4][matrix[i][j] & 0x0f];
		}
	}
}

void Rijndeal_128::ShiftRows(byte * matrix[], CryptingMode cm) {
	byte tmp;
	XorSwap(matrix[2][0], matrix[2][2]);
	XorSwap(matrix[2][1], matrix[2][3]);
	if(cm == encrypt) {
		tmp = matrix[1][0];
		matrix[1][0] = matrix[1][1];
		matrix[1][1] = matrix[1][2];
		matrix[1][2] = matrix[1][3];
		matrix[1][3] = tmp;
		tmp = matrix[3][0];
		matrix[3][0] = matrix[3][3];
		matrix[3][3] = matrix[3][2];
		matrix[3][2] = matrix[3][1];
		matrix[3][1] = tmp;
		return;
	}
	tmp = matrix[1][0];
	matrix[1][0] = matrix[1][3];
	matrix[1][3] = matrix[1][2];
	matrix[1][2] = matrix[1][1];
	matrix[1][1] = tmp;
	tmp = matrix[3][0];
	matrix[3][0] = matrix[3][1];
	matrix[3][1] = matrix[3][2];
	matrix[3][2] = matrix[3][3];
	matrix[3][3] = tmp;
}

void Rijndeal_128::MixColumns(byte * matrix[], CryptingMode cm) {
	byte tmp[4];
	byte i, j, k;
	for(i = 0; i < 4; ++i) {
		for(j = 0; j < 4; ++j) {
			tmp[j] = matrix[j][i];
			matrix[j][i] = 0;
		}
		for(j = 0; j < 4; ++j) {
			for(k = 0; k < 4; ++k) {
				matrix[j][i] ^= cm == encrypt ? ModTime(tmp[k], MIX_MATRIX[j][k]) : 
					ModTime(tmp[k], MIX_MATRIX_INV[j][k]);
			}
		}
	}
}

void Rijndeal_128::AddRoundKey(byte * matrix[], byte round, CryptingMode cm) {
	byte i, j;
	byte* keyinv[4];
	if(cm == encrypt) {
		for(i = 0; i < 4; ++i) {
			for(j = 0; j < 4; ++j) {
				matrix[i][j] ^= extendkey[i][round * 4 + j];
			}
		}
	}
	else {
		if(round == 0 || round == 10) {
			for(i = 0; i < 4; ++i) {
				for(j = 0; j < 4; ++j) {
					matrix[i][j] ^= extendkey[i][0x2c - (round + 1) * 4 + j];
				}
			}
		}
		else {
			for(i = 0; i < 4; ++i) {
				keyinv[i] = new byte[4];
				for(j = 0; j < 4; ++j) {
					keyinv[i][j] = extendkey[i][0x2c - (round + 1) * 4 + j];
				}
			}
			MixColumns(keyinv, cm);
			for(i = 0; i < 4; ++i) {
				for(j = 0; j < 4; ++j) {
					matrix[i][j] ^= keyinv[i][j];
				}
				delete[] keyinv[i];
			}
		}
	}
}