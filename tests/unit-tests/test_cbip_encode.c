#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "cbip_encode.h"

#define ENCODER_CHECK(message) \
	if (status < 0) {\
		printf("%s\n", message);\
		return 1;\
	}

#ifndef UNUSED
#define UNUSED(x) ((void)x)
#endif

static int test_rejects_wrapped_length(void) {
	unsigned char data[16] = {0};
	unsigned char value = 0;
	cbipEncoder_t encoder;

	cbip_encoder_init(&encoder, data, sizeof(data));
	encoder.offset = 8;

	int status = cbip_add_byte_string(&encoder, &value, UINT32_MAX - 8);
	if ((status >= 0) || !encoder.fault) {
		printf("Encoder accepted a wrapped byte-string length\n");
		return 1;
	}
	return 0;
}

static int test_rejects_null_source(void) {
	unsigned char data[16] = {0};
	cbipEncoder_t encoder;

	/* A NULL source with a nonzero length is refused and latches fault. */
	cbip_encoder_init(&encoder, data, sizeof(data));
	if ((cbip_add_byte_string(&encoder, NULL, 4) >= 0) || !encoder.fault) {
		printf("Encoder accepted a NULL byte-string source\n");
		return 1;
	}

	/* A NULL source with a zero length stays valid: an empty string is legal CBOR
	   and no copy is made. Runs under UBSan, so a memmove() here would be caught. */
	cbip_encoder_init(&encoder, data, sizeof(data));
	if ((cbip_add_byte_string(&encoder, NULL, 0) < 0) || encoder.fault) {
		printf("Encoder rejected an empty byte string\n");
		return 1;
	}

	/* Same for a text string, which shares cbip_add_raw(). */
	cbip_encoder_init(&encoder, data, sizeof(data));
	if ((cbip_add_string(&encoder, NULL, 4) >= 0) || !encoder.fault) {
		printf("Encoder accepted a NULL text-string source\n");
		return 1;
	}
	return 0;
}

int main(int argc, char **argv) {
	unsigned char aaguid[16] = { 0xf4,0x60,0xd3,0xbf,0xf8,0x61,0xcf,0xe2,0xf1,0x90,0x9d,0x06,0xf9,0x8c,0x7c,0x83 };
	unsigned char data[1024];
	FILE *fic;
	cbipEncoder_t encoder;
	int status;

	UNUSED(argc);
	UNUSED(argv);

	if (test_rejects_wrapped_length() != 0) {
		return 1;
	}

	if (test_rejects_null_source() != 0) {
		return 1;
	}

	status = cbip_encoder_init(&encoder, data, sizeof(data));
	ENCODER_CHECK("Initialize encoder failed");

	cbip_add_map_header(&encoder, 7);
	ENCODER_CHECK("Encoder failed 1\n");

	status = cbip_add_int(&encoder, 1);
	ENCODER_CHECK("Encoder failed 2\n");
	status = cbip_add_array_header(&encoder, 2);
	ENCODER_CHECK("Encoder failed 3\n");
	status = cbip_add_string(&encoder, "U2F_V2", sizeof("U2F_V2") - 1);
	ENCODER_CHECK("Encoder failed 4\n");
	status = cbip_add_string(&encoder, "FIDO_2_0", sizeof("FIDO_2_0") - 1);
	ENCODER_CHECK("Encoder failed 5\n");

	status = cbip_add_int(&encoder, 3);
	ENCODER_CHECK("Encoder failed 6\n");	
	status = cbip_add_byte_string(&encoder, aaguid, sizeof(aaguid));
	ENCODER_CHECK("Encoder failed 7\n");	

	status = cbip_add_int(&encoder, 4);
	ENCODER_CHECK("Encoder failed 8\n");	
	status = cbip_add_map_header(&encoder, 3);
	ENCODER_CHECK("Encoder failed 9\n");
	status = cbip_add_string(&encoder, "rk", sizeof("rk") - 1);
	ENCODER_CHECK("Encoder failed 10\n");
	status = cbip_add_boolean(&encoder, true);
	ENCODER_CHECK("Encoder failed 11\n");
	status = cbip_add_string(&encoder, "up", sizeof("up") - 1);
	ENCODER_CHECK("Encoder failed 12\n");
	status = cbip_add_boolean(&encoder, true);
	ENCODER_CHECK("Encoder failed 13\n");
	status = cbip_add_string(&encoder, "uv", sizeof("uv") - 1);
	ENCODER_CHECK("Encoder failed 14\n");
	status = cbip_add_boolean(&encoder, true);
	ENCODER_CHECK("Encoder failed 15\n");

	status = cbip_add_int(&encoder, 5);
	ENCODER_CHECK("Encoder failed 16\n");	
	status = cbip_add_int(&encoder, 1024);
	ENCODER_CHECK("Encoder failed 17\n");	

	fic = fopen("getinfo.cbor", "wb");
	fwrite(data, encoder.offset, 1, fic);
	fclose(fic);

	return 0;
}
