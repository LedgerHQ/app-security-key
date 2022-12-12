#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include "cbip_decode.h"

void display_item(uint8_t *buffer, cbipItem_t *item) {
	switch(item->type) {
		case cbipInt:
			printf("Int %d\n", item->value);
			break;
		case cbipNegativeInt:
			printf("Negative int %d\n", -1 - item->value);
			break;
		case cbipByteString: {
			uint32_t i;
			printf("Bytestring ");
			for (i=0; i<item->value; i++) {
				printf("%.2x", buffer[item->offset + item->headerLength + i]);
			}
			printf("\n");
			break;
		}
		case cbipTextString: {
			uint32_t i;
			printf("String ");
			for (i=0; i<item->value; i++) {
				printf("%c", buffer[item->offset + item->headerLength + i]);
			}
			printf("\n");
			break;
		}
		case cbipArray: 
			printf("Array of %d elements\n", item->value);
			break;
		case cbipMap:
			printf("Map of %d elements\n", item->value);
			break;
		case cbipTrue:
			printf("True\n");
			break;
		case cbipFalse:
			printf("False\n");
			break;
		case cbipNone:
			// This cannot happen, because None marks the end of data.
			// Silence -Wswitch warning anyway.
			assert(item->type != cbipNone);
			break;
	}
}

int main(int argc, char **argv) {
	FILE *fic;
	size_t size;
	ssize_t read_size;
	unsigned char *data;
	cbipDecoder_t decoder;
	cbipItem_t item;
	int status;
	bool first = true;
	if (argc < 2) {
		printf("Usage : %s filename\n", argv[0]);
		return 1;
	}
	fic = fopen(argv[1], "rb");
	if (fic == NULL) {
		printf("Failed to open %s\n", argv[1]);
		return 1;
	}
	fseek(fic, 0, SEEK_END);
	size = ftell(fic);
	data = malloc(size);
	if (data == NULL) {
		printf("Failed to allocate memory\n");
		fclose(fic);
		return 1;
	}
	fseek(fic, 0, SEEK_SET);
	read_size = fread(data, 1, size, fic);
	if ((size_t)read_size != size) {
		printf("Reading the file failed\n");
		free(data);
		return 1;
	}
	fclose(fic);
	status = cbip_decoder_init(&decoder, data, size);
	if (status < 0) {
		printf("Decoder init failed\n");
		free(data);
		return 1;
	}
	for (;;) {
		if (first) {
			status = cbip_first(&decoder, &item);		
			first = false;
		}
		else {
			status = cbip_next(&decoder, &item);
		}
		if (status < 0) {
			printf("read item failed\n");
			free(data);
			return 1;
		}
		if (item.type == cbipNone) {
			break;
		}
		display_item(data, &item);
	}	
	free(data);
	return 0;
}
