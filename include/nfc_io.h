/*
*******************************************************************************
*   Ledger App Security Key
*   (c) 2024 Ledger
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

#ifdef HAVE_NFC
void nfc_io_set_le(uint32_t le);
void nfc_io_set_response_ready(uint16_t sw, uint16_t len, const char *status);
bool nfc_io_is_response_pending(void);
int nfc_io_send_prepared_response(void);

#else
static inline void nfc_io_set_le(uint32_t le) {
    return;
}

static inline void nfc_io_set_response_ready(uint16_t sw, uint16_t len, const char *status) {
    UNUSED(sw);
    UNUSED(len);
    UNUSED(status);
    return;
}

static inline bool nfc_io_is_response_pending(void) {
    return false;
}

static inline int nfc_io_send_prepared_response(void) {
    return -1;
}
#endif
