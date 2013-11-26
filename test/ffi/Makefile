obj-m += funct.o

all: funct_mod cparser_test

funct_mod:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

INC=../../include
U_DIR=../../userspace
INTP=../../interpreter
U_FFI_DIR=$(U_DIR)/ffi
CPARSER_FILES=cparser.o ctype.o ffi_type.o
KTAPC_CFLAGS = -Wall -O2

cparser.o: $(U_FFI_DIR)/cparser.c $(INC)/*
	$(CC) -DCONFIG_KTAP_FFI -o $@ -c $<

ctype.o: $(U_FFI_DIR)/ctype.c $(INC)/*
	$(CC) -DCONFIG_KTAP_FFI -o $@ -c $<

ffi_type.o: $(INTP)/ffi/ffi_type.c $(INC)/*
	$(CC) -DCONFIG_KTAP_FFI -o $@ -c $<

cparser_test: cparser_test.c $(CPARSER_FILES) $(INC)/*
	$(CC) -DCONFIG_KTAP_FFI -I$(INC) -I$(U_DIR) $(KTAPC_CFLAGS) \
		-o $@ $< $(CPARSER_FILES)

load:
	insmod funct.ko

unload:
	rmmod funct

test: all
	@echo "------------ Test cparser now -----------"
	./cparser_test
	@echo "------------ Test ffi.current now ------------"
	../../ktap current.kp
	@echo "------------ Test ffi module now ------------"
	rmmod funct > /dev/null 2>&1 || true
	insmod funct.ko
	../../ktap ufunct.kp
	../../ktap kfunct.kp
	rmmod funct.ko

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -rf cparser_test
