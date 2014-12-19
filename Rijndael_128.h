#pragma once

typedef unsigned char byte;

namespace securasu {
	enum CryptingMode {
		encrypt,
		decrypt
	};
	
	class Rijndeal_128 {
	private:
		static const byte S_BOX[0x10][0x10];
		static const byte S_BOX_INV[0x10][0x10];
		static const byte RCON[0x04][0x0a];
		static const byte MIX_MATRIX[0x04][0x04];
		static const byte MIX_MATRIX_INV[0x04][0x04];
		byte key[0x10];
		byte plaintext[0x10];
		byte ciphertext[0x10];
		byte extendkey[0x04][0x2c];
		void SubBytes(byte * matrix[], CryptingMode cm);
		void ShiftRows(byte * matrix[], CryptingMode cm);
		void MixColumns(byte * matrix[], CryptingMode cm);
		void AddRoundKey(byte * matrix[], byte round, CryptingMode cm);
		void KeyExpansion();
	public:
		Rijndeal_128();
		static byte XTime(byte x);
		static byte ModTime(byte x, byte y);
		static bool ByteCopy(byte * dst, byte * src);
		static void XorSwap(byte& x, byte& y);
		void Crypt(CryptingMode cm);
		void setKey(byte * kk);
		byte * getKey();
		void setPlainText(byte * pp);
		byte * getPlainText();
		void setCipherText(byte * cc);
		byte * getCipherText();
	};

	inline Rijndeal_128::Rijndeal_128() {
		int i;
		for(i = 0; i < 0x10; ++i) {
			key[i] = 0;
			plaintext[i] = 0;
			ciphertext[i] = 0;
		}
	}

	inline void Rijndeal_128::setKey(byte * kk) {
		ByteCopy(key, kk);
	}

	inline byte * Rijndeal_128::getKey() {
		return key;
	}

	inline void Rijndeal_128::setPlainText(byte * pp) {
		ByteCopy(plaintext, pp);
	}

	inline byte * Rijndeal_128::getPlainText() {
		return plaintext;
	}

	inline void Rijndeal_128::setCipherText(byte * cc) {
		ByteCopy(ciphertext, cc);
	}

	inline byte * Rijndeal_128::getCipherText() {
		return ciphertext;
	}

	inline byte Rijndeal_128::XTime(byte x) {
		return (x & 0x80) ? ((x << 1) ^ (0x1b)) : (x << 1);
	}

	inline byte Rijndeal_128::ModTime(byte x, byte y) {
		byte result = 0;
		while(y) {
			if(y & 0x01)
				result ^= x;
			x = XTime(x);
			y >>= 1;
		}
		return result;
	}

	inline bool Rijndeal_128::ByteCopy(byte * dst, byte * src) {
		byte count = 0;
		while(*(dst++) = *(src++))
			if(++count == 0x10)
				break;
		return !(*src);
	}

	inline void Rijndeal_128::XorSwap(byte& x, byte& y) {
		x ^= y;
		y ^= x;
		x ^= y;
	}
}