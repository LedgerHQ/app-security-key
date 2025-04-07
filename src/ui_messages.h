/*
*******************************************************************************
*   Ledger App Security Key
*   (c) 2025 Ledger
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

#pragma once

#ifdef DEBUG_UI
#define CTAP2_LOGIN                  "CTAP2 - Login request\nsigned"
#define CTAP2_LOGIN_CANCELLED        "CTAP2 - Login cancelled"
#define CTAP2_REGISTRATION           "CTAP2 - Registration\ndetails sent"
#define CTAP2_REGISTRATION_CANCELLED "CTAP2 - Registration\ncancelled"
#define U2F_LOGIN                    "U2F - Login request\nsigned"
#define U2F_LOGIN_CANCELLED          "U2F - Login request\nsigned cancelled"
#define U2F_REGISTRATION             "U2F - Registration\ndetails sent"
#define U2F_REGISTRATION_CANCELLED   "U2F - Registration\ncancelled"
#else
#define CTAP2_LOGIN                  "Login request signed"
#define CTAP2_LOGIN_CANCELLED        "Login cancelled"
#define CTAP2_REGISTRATION           "Registration details\nsent"
#define CTAP2_REGISTRATION_CANCELLED "Registration cancelled"
#define U2F_LOGIN                    CTAP2_LOGIN
#define U2F_LOGIN_CANCELLED          CTAP2_LOGIN_CANCELLED
#define U2F_REGISTRATION             CTAP2_REGISTRATION
#define U2F_REGISTRATION_CANCELLED   CTAP2_REGISTRATION_CANCELLED
#endif
