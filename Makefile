VER_FILE := version
VERSION := $(shell head -1 ${VER_FILE})


NAME=file
OUT_IDS=./bin/$(NAME)s
OUT_FC=./bin/$(NAME)fc
OUT_C=./bin/$(NAME)c
OUT_D=./bin/debugc
OUT_SENDD=./bin/sendd


CC=/usr/bin/gcc
SOURCE=./source
# DATE=`/bin/date +%F`
#
# library
#
OUT_C-CLIENT-LIB=$(SOURCE)/common-client.o $(SOURCE)/read_file.o $(SOURCE)/xml_parse.o $(SOURCE)/send_packet.o $(SOURCE)/wlog.o $(SOURCE)/send_request.o $(SOURCE)/bind_port.o $(SOURCE)/strfind.o $(SOURCE)/decode.o  
OUT_C-SERVER_LIB=$(SOURCE)/tcp_server.o  $(SOURCE)/common.o
OUT_C-CMCORE=$(SOURCE)/cmcore.o

RM=/bin/rm
CFLAGS=-Wall -g -ggdb -DNETBONE -D_FILE_OFFSET_BITS=64 -O2 -lpthread -lz -lrt  -rdynamic -Wno-unused-but-set-variable
CFLAGS_BIN=$(CFLAGS) -lcmcore

all:  lib client debug sendd ids 

debug:
	$(CC) $(CFLAGS_BIN) -o $(OUT_D) $(SOURCE)/debug.c $(OUT_C-CLIENT-LIB) 
fuse:
	$(CC) $(CFLAGS_BIN) -o $(OUT_FC) -lfuse $(SOURCE)/fuse-client.c $(OUT_C-CLIENT-LIB) 
client:
	$(CC) $(CFLAGS_BIN) -o $(OUT_C) $(SOURCE)/client.c $(OUT_C-CLIENT-LIB) 
	#
	# this is for external (non FID) users to use this IDS evironment (to join to shared memory)
	#
	chmod u+s  $(OUT_C)
sendd:
	$(CC) $(CFLAGS_BIN) -o $(OUT_SENDD)  $(SOURCE)/sendd.c $(OUT_C-CLIENT-LIB) $(OUT_C-SERVER_LIB)
ids:
	$(CC) $(CFLAGS_BIN) -o $(OUT_IDS) -DVERSION='"$(VERSION)"' $(SOURCE)/datad.c $(OUT_C-CLIENT-LIB)  $(OUT_C-SERVER_LIB)


cmcore:
	$(CC) $(CFLAGS) -c -fPIC -o $(OUT_C-CMCORE) $(SOURCE)/cmcore.c
	$(CC) -shared -Wl,-soname,libcmcore.so.1 -Wl,-init,cm_init -o $(SOURCE)/libcmcore.so.1.0.1 $(OUT_C-CMCORE)
	# mv /home/test/get/netbone/source/libcmcore.so.1.0.1 /usr/lib
	# for gcc: ln /usr/lib/libcmcore.so.1.0.1 /usr/lib/libcmcore.so 
	# for ldd: ln /usr/lib/libcmcore.so.1.0.1 /usr/lib/libcmcore.so.1
	# ldconfig to refresh ld.so :)

lib:
	@for library in bind_port wlog send_request common common-client read_file  xml_parse send_packet strfind decode tcp_server; do \
	echo $(CC) $(CFLAGS) -c -o $(SOURCE)/$$library.o $(SOURCE)/$$library.c ; \
	 $(CC) $(CFLAGS) -c -o $(SOURCE)/$$library.o $(SOURCE)/$$library.c ; \
	done

clean: clean-ids clean-lib clean-client clean-fuse 

clean-source:
	$(RM) source/*.c

clean-ids:
	$(RM) $(OUT_IDS)
clean-fuse:
	 $(RM) $(OUT_FC)
clean-client:
	$(RM) $(OUT_C)
clean-lib:
	$(RM) $(OUT_C-CLIENT-LIB)
ver:
	../scripts_admin/netbone.pl version
