/*
*******************************************************************************
*   Ledger App Security Key
*   (c) 2022 Ledger
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*   Unless required by applicable law or agreed to in writing, software
*   distributed under the License is distributed on an "AS IS" BASIS,
*   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*   limitations under the License.
********************************************************************************/

#ifndef __CBIP_INTERNAL_H__

#define __CBIP_INTERNAL_H__

#define CBOR_TYPE_MASK 0xE0
#define CBOR_INFO_BITS 0x1F

#define CBOR_UNSIGNED_INT (0b000 << 5)
#define CBOR_NEGATIVE_INT (0b001 << 5)
#define CBOR_BYTE_STRING  (0b010 << 5)
#define CBOR_TEXT_STRING  (0b011 << 5)
#define CBOR_ARRAY        (0b100 << 5)
#define CBOR_MAP          (0b101 << 5)
#define CBOR_PRIMITIVE    (0b111 << 5)

#define CBOR_LEN_U8  0x18
#define CBOR_LEN_U16 0x19
#define CBOR_LEN_U32 0x1A

#define CBOR_FALSE 0x14
#define CBOR_TRUE  0x15

#endif
