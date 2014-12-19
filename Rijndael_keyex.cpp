#include "Rijndael_128.h"

using namespace securasu;

void Rijndeal_128::KeyExpansion() {
	byte i, j;
	byte tmp[4], t;
	for(i = 0; i < 4; ++i) {
		for(j = 0; j < 4; ++j) {
			extendkey[j][i] = key[i * 4 + j];
		}
	}
	for(j = 4; j < 44; ++j) {
		for(i = 0; i < 4; ++i) {
			tmp[i] = extendkey[i][j - 1];
		}
		if(j % 4 == 0) {
			t = tmp[0];
			tmp[0] = tmp[1];
			tmp[1] = tmp[2];
			tmp[2] = tmp[3];
			tmp[3] = t;
			for(i = 0; i < 4; ++i) {
				tmp[i] = S_BOX[tmp[i] >> 4][tmp[i] & 0x0f] ^ RCON[i][j / 4 - 1];
			}
		}
		for(i = 0; i < 4; ++i) {
			extendkey[i][j] = extendkey[i][j - 4] ^ tmp[i];
		}
	}
}