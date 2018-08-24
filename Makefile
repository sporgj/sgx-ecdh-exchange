include enclave/header.mk

INCLUDES = -I$(SGX_SDK)/include
LIBS := -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -lpthread -Wl,-rpath=$(CURDIR)\
			-lmbedcrypto -lmbedtls -lcurl -pthread

ifneq ($(SGX_MODE), HW)
	LIBS += -lsgx_uae_service_sim
else
	LIBS += -lsgx_uae_service
endif

CFLAGS := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(INCLUDES)
CPPFLAGS := $(CFLAGS) -std=c++11
CFLAGS := -std=gnu11 $(CFLAGS)


main_objs := \
	enclave_u.o \
	ocalls.o \
	storage.o \
	protocol.o \
	quote.o \
	main.o

libnexus_objs := \
	nexus_encode.o \
	nexus_util.o \
	nexus_raw_file.o \
	nexus_json.o \
	nxjson.o

objs := $(main_objs) $(foreach o,$(libnexus_objs),libnexus/$(o))


build = \
        @if [ -z "$V" ]; then \
                echo '    [$1]  $@'; \
                $2; \
        else \
                echo '$2'; \
                $2; \
        fi


prog := xchg-secret

all: $(prog)
	make -C enclave


$(prog): $(objs)
	$(call build,CC,$(CC) $(CFLAGS) $^ -o $@ $(LIBS))

enclave_u.c: enclave/enclave.edl
	$(call build,SGX,$(SGX_EDGER8R) --untrusted --untrusted-dir ./ $^)

enclave_u.o: enclave_u.c
	$(call build,CC,$(CC) $(CFLAGS) -c $< -o $@)

%.o: %.c
	$(call build,CC,$(CC) $(CFLAGS) -c $< -o $@)

.PHONY: clean
clean:
	rm -rf $(prog) $(objs) enclave_u.*
	make clean -C enclave
