CFLAGS = 
ifdef AES192
CFLAGS += -DAES192=1
endif
ifdef AES256
CFLAGS += -DAES256=1
endif

INCLUDE_PATH = .

default: build

clean:
	rm -f *.OBJ *.LST *.o *.gch *.out *.hex *.map *.elf *.a

build: AES.cu AES.h
	nvcc AES.cu -o test.o $(CFLAGS)

test:
	make clean && make && ./test.o
	make clean && make AES192=1 && ./test.o
	make clean && make AES256=1 && ./test.o