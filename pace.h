#pragma once

#include "passy_reader.h"
#include <stdio.h>
#include <stdlib.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/aes.h>
#include "string.h"
#include "assert.h"

typedef struct {
    PassyReader* reader;

} pace_auth_params;

typedef struct {
    uint8_t KSenc[16];
    uint8_t KSmac[16];
} pace_auth_result;

NfcCommand perform_pace_auth(PassyReader* reader);
