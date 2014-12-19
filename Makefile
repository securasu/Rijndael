CXX = clang++
CXXFLAGS = -O2 -DNDEBUG

all: rijndael

rijndael: librijndael.dylib Rijndael_main.o
	$(CXX) $(CXXFLAGS) $^ -o $@

librijndael.dylib: Rijndael_const.o Rijndael_crypt.o Rijndael_keyex.o Rijndael_roundopr.o
	$(CXX) $(CXXFLAGS) -shared $^ -o $@

.cpp.o:
	$(CXX) $(CXXFLAGS) -c $<

Rijndael_const.o: Rijndael_const.cpp Rijndael_128.h

Rijndael_crypt.o: Rijndael_crypt.cpp Rijndael_128.h

Rijndael_keyex.o: Rijndael_keyex.cpp Rijndael_128.h

Rijndael_roundopr.o: Rijndael_roundopr.cpp Rijndael_128.h

Rijndael_main.o: Rijndael_main.cpp Rijndael_128.h

clean:
	rm -f rijndael
	rm -f *.o
	rm -f librijndael.dylib
