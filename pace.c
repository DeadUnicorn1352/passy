#include "stdio.h"
#include "stdlib.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/aes.h"
#include "mbedtls/psa_util.h"
#include "string.h"
#include "assert.h"
#include "pace.h"

#define TAG "PaceAuth"

// class
#define V_ASN1_UNIVERSAL        0x00
#define V_ASN1_APPLICATION      0x40
#define V_ASN1_CONTEXT_SPECIFIC 0x80

#define V_ASN1_PRIVATE       0xC0
#define V_ASN1_PRIMITIVE_TAG 0x1F
#define V_ASN1_CONSTRUCTED   0x20

#define NONCE_SIZE 16

int f_rng(void*, unsigned char* buff, size_t size) {
    furi_hal_random_fill_buf(buff, size);
    //passy_log_buffer(TAG, "frng", buff, size);
    return 0;
}

NfcCommand send_mse_at(PassyReader* passy_reader, uint8_t enc_nonce[NONCE_SIZE]) {
    FURI_LOG_D(TAG, "start send_mse_at");
    uint8_t lc = 0x0F; // todo: constant lc
    uint8_t header[5] = {0x00, 0x22, 0xC1, 0xA4, lc};
    enum pass_type {
        MRZ = 0x01,
        CAN = 0x02,
        PIN = 0x03
    };
    uint8_t pace_ecdh_genmap_aes128[12] = {
        0x80, 0x0A, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x02};
    uint8_t pass[3] = {0x83, 0x01, MRZ};

    // todo can be optimized
    uint8_t payload[sizeof(header) + sizeof(pace_ecdh_genmap_aes128) + sizeof(pass)];
    memcpy(payload, header, sizeof(header));
    memcpy(payload + sizeof(header), pace_ecdh_genmap_aes128, sizeof(pace_ecdh_genmap_aes128));
    memcpy(payload + sizeof(header) + sizeof(pace_ecdh_genmap_aes128), pass, sizeof(pass));
    bit_buffer_append_bytes(passy_reader->tx_buffer, payload, sizeof(payload));
    NfcCommand ret = passy_reader_send(passy_reader);
    if(ret != NfcCommandContinue) {
        FURI_LOG_I(TAG, "error send_mse_at");
        return ret;
    }

    uint8_t nonce_query[8] = {0x10, 0x86, 0x00, 0x00, 0x02, 0x7C, 0x00, 0x00};
    bit_buffer_append_bytes(passy_reader->tx_buffer, nonce_query, sizeof(nonce_query));
    // FuriThread.
    ret = passy_reader_send(passy_reader);
    if(ret != NfcCommandContinue) {
        FURI_LOG_I(TAG, "error query nonce");
        return ret;
    }
    bit_buffer_write_bytes(passy_reader->rx_buffer, enc_nonce, NONCE_SIZE);

    FURI_LOG_D(TAG, "success? send_mse_at and query nonce");
    return ret;
}

enum DATA_TAG {
    NONE = -1,

    // According to TR-03110-3, chapter B.(1|2|3), B.14.* and C3.2
    CERTIFICATE_EXTENSION_CONTENT_0 = 0,
    CRYPTOGRAPHIC_MECHANISM_REFERENCE = 0,
    CA_EPHEMERAL_PUBLIC_KEY = 0,
    MAPPING_DATA = 1,
    RI_FIRST_IDENTIFIER = 1,
    PACE_EPHEMERAL_PUBLIC_KEY = 3,
    PASSWORD_REFERENCE = 3,
    PUBLIC_KEY_REFERENCE = 3,
    PRIVATE_KEY_REFERENCE = 4,
    AUTHENTICATION_TOKEN = 5,
    EC_PUBLIC_POINT = 6,
    AUXILIARY_AUTHENTICATED_DATA = 7,
    TA_EPHEMERAL_PUBLIC_KEY = 17,
    DYNAMIC_AUTHENTICATION_DATA = 28,
    CV_CERTIFICATE = 33,
    CERTIFICATE_SIGNATURE = 55,
    PUBLIC_KEY = 73,
    CERTIFICATE_HOLDER_AUTHORIZATION_TEMPLATE = 76,
    CERTIFICATE_BODY = 78,

    // According to ASN.1
    UNI_BOOLEAN = 1,
    UNI_INTEGER = 2,
    UNI_BITSTRING = 3,
    UNI_OCTETSTRING = 4,
    UNI_NULL = 5,
    UNI_OBJECT_IDENTIFIER = 6,
    UNI_SEQUENCE = 16,
    UNI_SET = 17
};

int ASN1_object_size(int constructed, int length, int tag) {
    int ret = 1;

    if(length < 0) return -1;
    if(tag >= 31) {
        while(tag > 0) {
            tag >>= 7;
            ret++;
        }
    }
    if(constructed == 2) {
        ret += 3;
    } else {
        ret++;
        if(length > 127) {
            int tmplen = length;
            while(tmplen > 0) {
                tmplen >>= 8;
                ret++;
            }
        }
    }
    if(ret >= INT_MAX - length) return -1;
    return ret + length;
}

void asn1_put_length(uint8_t** pp, int length) {
    uint8_t* p = *pp;
    int i, len;

    if(length <= 127) {
        *(p++) = (uint8_t)length;
    } else {
        len = length;
        for(i = 0; len > 0; i++)
            len >>= 8;
        *(p++) = i | 0x80;
        len = i;
        while(i-- > 0) {
            p[i] = length & 0xff;
            length >>= 8;
        }
        p += len;
    }
    *pp = p;
}

void ASN1_put_object(uint8_t** pp, int constructed, int length, int tag, int xclass) {
    uint8_t* p = *pp;
    int i, ttag;

    i = (constructed) ? V_ASN1_CONSTRUCTED : 0;
    i |= (xclass & V_ASN1_PRIVATE);
    if(tag < 31) {
        *(p++) = i | (tag & V_ASN1_PRIMITIVE_TAG);
    } else {
        *(p++) = i | V_ASN1_PRIMITIVE_TAG;
        for(i = 0, ttag = tag; ttag > 0; i++)
            ttag >>= 7;
        ttag = i;
        while(i-- > 0) {
            p[i] = tag & 0x7f;
            if(i != (ttag - 1)) p[i] |= 0x80;
            tag >>= 7;
        }
        p += ttag;
    }
    if(constructed == 2)
        *(p++) = 0x80;
    else
        asn1_put_length(&p, length);
    *pp = p;
}

typedef struct {
    uint8_t* data; // must be freed after use
    size_t size;
} bin_array;

bin_array bin_array_alloc(size_t size) {
    uint8_t* data = calloc(size, sizeof(uint8_t));
    return (bin_array){.data = data, .size = size};
}

bin_array bin_array_concat(bin_array a1, bin_array a2) {
    bin_array res = bin_array_alloc(a1.size + a2.size);
    uint8_t* p = memcpy(res.data, a1.data, a1.size);
    memcpy(p + a1.size, a2.data, a2.size);
    return res;
}

void bin_array_free(bin_array* arr) {
    free(arr->data);
    arr->data = NULL;
    arr->size = 0;
}

bin_array asn1_encode(const uint8_t* data, size_t data_size, int class, int tag, int constructed) {
    const int size = ASN1_object_size(constructed, data_size, tag);
    bin_array result = bin_array_alloc(size);
    uint8_t* p = result.data;
    ASN1_put_object(&p, constructed, data_size, tag, class);

    assert(result.data + result.size == p + data_size);
    // p should be incremented
    memcpy(p, data, data_size);
    return result;
}

void hex_to_char(const char* hex_str, uint8_t* out, uint8_t out_len) {
    int i_len = strlen(hex_str);

    uint8_t idx = 0, oi = 0;
    unsigned int val = 0;
    while(idx < i_len && oi < out_len) {
        sscanf(hex_str + idx, "%2x", &val);
        out[oi] = val;
        idx += 2;
        oi++;
    }
}

bin_array encode_pub(uint8_t* public_point, size_t point_size) {
    // pace oid ? 04 00 7F 00 07 02 02 04 02 02
    const uint8_t pace_id[] = {0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x02};

    /*
	const QByteArray oID = Asn1Util::encode(V_ASN1_UNIVERSAL, ASN1Struct::UNI_OBJECT_IDENTIFIER, QByteArray(pOid));
	const QByteArray publicPoint = Asn1Util::encode(V_ASN1_CONTEXT_SPECIFIC, ASN1Struct::EC_PUBLIC_POINT, pKey);
	return Asn1Util::encode(V_ASN1_APPLICATION, ASN1Struct::PUBLIC_KEY, oID + publicPoint, true);
	 */

    bin_array oid =
        asn1_encode(pace_id, sizeof(pace_id), V_ASN1_UNIVERSAL, UNI_OBJECT_IDENTIFIER, 0);
    bin_array ecpoint =
        asn1_encode(public_point, point_size, V_ASN1_CONTEXT_SPECIFIC, EC_PUBLIC_POINT, 0);
    bin_array concat = bin_array_concat(oid, ecpoint);
    bin_array encoded =
        asn1_encode(concat.data, concat.size, V_ASN1_APPLICATION, PUBLIC_KEY, V_ASN1_CONSTRUCTED);

    bin_array_free(&oid);
    bin_array_free(&ecpoint);
    bin_array_free(&concat);

    return encoded;
}

char* strcat(char* b1, const char* b2) {
    const char* b2_p = b2;
    char* b1_p = b1;
    while(*b2_p != '\0') {
        *b1_p = *b2_p;
        b1_p++;
        b2_p++;
    }
    return b1_p;
}

int get_nonce(PassyReader* passy_reader, mbedtls_mpi* dec_nonce) {
    uint8_t enc_nonce[NONCE_SIZE] = {0};
    if(send_mse_at(passy_reader, enc_nonce) != NfcCommandContinue) {
        FURI_LOG_I(TAG, "send_mse_at failed");
        return -4;
    }

    uint8_t mrz_sha1[20] = {0};
    char* doc_n = passy_reader->passy->passport_number;
    char* dob = passy_reader->passy->date_of_birth;
    char* doe = passy_reader->passy->date_of_expiry;
    uint8_t mrz_buf[strlen(doc_n) + strlen(dob) + strlen(doe)];
    memset(mrz_buf, 0, sizeof(mrz_buf));
    uint8_t* mrz = (uint8_t*)strcat(strcat(strcat((char*)mrz_buf, doc_n), dob), doe);
    if(mbedtls_sha1(mrz, sizeof(mrz_buf), mrz_sha1)) {
        FURI_LOG_I(TAG, "sha1 failed");
        return -1;
    }
    // correct - 7e2d2a41c74ea0b38cd36f863939bfa8e9032aad
    passy_log_buffer(TAG, "mrz_sha:", mrz_sha1, sizeof(mrz_sha1));

    uint8_t emrz_buf[sizeof(mrz_sha1) + 4] = {0};
    memcpy(emrz_buf, mrz_sha1, sizeof(mrz_sha1));
    //  KDF(enc_nonce, 3)
    emrz_buf[sizeof(emrz_buf) - 1] = 3;
    uint8_t kpi[20] = {0};
    if(mbedtls_sha1(emrz_buf, sizeof(emrz_buf), kpi)) {
        FURI_LOG_I(TAG, "sha1 failed");
        return -2;
    }
    passy_log_buffer(TAG, "kpi:", kpi, sizeof(kpi));

    mbedtls_aes_context aes_ctx;
    mbedtls_aes_init(&aes_ctx);
    int notok = mbedtls_aes_setkey_dec(&aes_ctx, kpi, 128);
    if(notok) {
        FURI_LOG_I(TAG, "error key\n");
        return -3;
    }
    uint8_t iv[16] = {0};
    uint8_t decrypted_nonce[16] = {0};
    notok = mbedtls_aes_crypt_cbc(
        &aes_ctx, MBEDTLS_AES_DECRYPT, sizeof(decrypted_nonce), iv, enc_nonce, decrypted_nonce);
    if(notok) {
        FURI_LOG_I(TAG, "error cbc\n");
        return -4;
    }

    passy_log_buffer(TAG, "decrypted_nonce:", decrypted_nonce, sizeof(decrypted_nonce));
    memcpy(dec_nonce, decrypted_nonce, sizeof(decrypted_nonce));

    return 0;
    // mse at
    // prepare mrz and shi
}

mbedtls_ecp_point get_mapping_data(const mbedtls_ecp_point* own_point) {
    UNUSED(own_point);
    mbedtls_ecp_point card_point;
    mbedtls_ecp_point_init(&card_point);
    // call generic authenticate
    const char* c1_x = "824FBA91C9CBE26BEF53A0EBE7342A3BF178CEA9F45DE0B70AA601651FBA3F57";
    const char* c1_y = "30D8C879AAA9C9F73991E61B58F4D52EB87A0A0C709A49DC63719363CCD13C54";
    if(mbedtls_ecp_point_read_string(&card_point, 16, c1_x, c1_y)) {
        FURI_LOG_I(TAG, "error reading card_point point\n");
    }
    return card_point;
}

mbedtls_ecp_point map_nonce(
    const mbedtls_mpi* nonce,
    const mbedtls_ecp_point* card_pub,
    const mbedtls_mpi* private,
    mbedtls_ecp_group* group) {
    mbedtls_ecp_point S;
    mbedtls_ecp_point_init(&S);
    int ret = mbedtls_ecp_mul(group, &S, private, card_pub, f_rng, NULL);
    if(ret) {
        FURI_LOG_I(TAG, "error mbedtls_ecp_mul\n");
        return (mbedtls_ecp_point){0};
    }

    mbedtls_mpi one;
    mbedtls_mpi_init(&one);
    mbedtls_mpi_add_int(&one, &one, 1);

    mbedtls_ecp_point mapped_G; // G~ = dec_nonce * G + shared_sec
    mbedtls_ecp_point_init(&mapped_G);

    ret = mbedtls_ecp_mul(group, &mapped_G, nonce, &S, f_rng, NULL);
    mbedtls_ecp_muladd(group, &mapped_G, nonce, &group->G, &one, &S);
    if(ret) {
        FURI_LOG_I(TAG, "error mbedtls_ecp_mul\n");
        return (mbedtls_ecp_point){0};
    }
    return mapped_G;
}

// need only 16 bytes as per 9.7.1.2 for aes-128
#define AES_128_KS_SIZE 16
#define KS_SIZE         AES_128_KS_SIZE

// [out] own_pub
// [out] card_point
int derive_shared_secret(
    uint8_t KSenc[KS_SIZE],
    uint8_t KSmac[KS_SIZE],
    mbedtls_ecp_group group,
    const mbedtls_ecp_point* G_tilda,
    mbedtls_ecp_point* own_pub,
    mbedtls_ecp_point* card_point) {
    UNUSED(own_pub);
    mbedtls_mpi priv;
    mbedtls_ecp_point pub;
    mbedtls_mpi_init(&priv);
    mbedtls_ecp_point_init(&pub);

    group.G = *G_tilda; //? mb not needed idk
    if(mbedtls_ecp_gen_keypair(&group, &priv, &pub, f_rng, NULL)) {
        FURI_LOG_I(TAG, "error generating ephermal keypair");
        return -1;
    }

    // todo need to do this in another function probably
    // send pub key and get client pub

    mbedtls_ecp_point_init(card_point);
    const char* c2_x = "9E880F842905B8B3181F7AF7CAA9F0EFB743847F44A306D2D28C1D9EC65DF6DB";
    const char* c2_y = "7764B22277A2EDDC3C265A9F018F9CB852E111B768B326904B59A0193776F094";
    if(mbedtls_ecp_point_read_string(card_point, 16, c2_x, c2_y)) {
        FURI_LOG_I(TAG, "error reading card_point point\n");
        return -2;
    }

    mbedtls_ecp_point H;
    mbedtls_ecp_point_init(&H);
    if(mbedtls_ecp_mul(&group, &H, &priv, card_point, f_rng, NULL)) {
        FURI_LOG_I(TAG, "error calculating secret\n");
        return -3;
    }

    mbedtls_mpi shared_secret_K = H.private_X; // need only x

    const uint8_t shared_sec_size = 32, c_size = 4, c_enc = 1, c_mac = 2;
    uint8_t kdf_input[shared_sec_size + c_size];
    memset(kdf_input, 0, sizeof(kdf_input));
    uint8_t kdf_res[20] = {0};
    int ret = mbedtls_mpi_write_binary(&shared_secret_K, kdf_input, shared_sec_size);
    if(ret) {
        FURI_LOG_I(TAG, "mbedtls_mpi_write_binary error\n");
        return -4;
    }

    kdf_input[35] = c_enc;
    ret = mbedtls_sha1(kdf_input, sizeof(kdf_input), kdf_res);
    if(ret) {
        FURI_LOG_I(TAG, "KS enc error\n");
        return -5;
    }
    memcpy(KSenc, kdf_res, KS_SIZE);
    memset(kdf_res, 0, sizeof(kdf_res));

    kdf_input[35] = c_mac;
    ret = mbedtls_sha1(kdf_input, sizeof(kdf_input), kdf_res);
    if(ret) {
        FURI_LOG_I(TAG, "KS mac error\n");
        return -6;
    }
    memcpy(KSmac, kdf_res, KS_SIZE);
    return 0;
}

int perform_mutual_auth(
    const uint8_t KSmac[KS_SIZE],
    const mbedtls_ecp_point* card_point,
    mbedtls_ecp_group* group) {
    UNUSED(KSmac);
    //mbedtls_aes_cmac_prf_128
    size_t olen = 0;
    uint8_t cpub2_uncomp[65] = {0};
    int ret = mbedtls_ecp_point_write_binary(
        group, card_point, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, cpub2_uncomp, sizeof(cpub2_uncomp));
    if(ret) {
        FURI_LOG_I(TAG, "mbedtls_ecp_point_write_binary error\n");
        return -1;
    }

    uint8_t cmac_buff[16] = {0};
    bin_array encoded_pub = encode_pub(cpub2_uncomp, sizeof(cpub2_uncomp));

    // todo
    const mbedtls_cipher_info_t* aes_cbc_info =
        mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB);
    ret = mbedtls_cipher_cmac(
        aes_cbc_info, KSmac, KS_SIZE * 8, encoded_pub.data, encoded_pub.size, cmac_buff);
    if(ret) {
        FURI_LOG_I(TAG, "cmac error\n");
        return -2;
    }

    //C2B0BD78 D94BA866
    uint8_t cmac[8];
    memcpy(cmac, cmac_buff, sizeof(cmac));
    passy_log_buffer(TAG, "cmac:", cmac, sizeof(cmac));

    // send cmac and verify 9000

    bin_array_free(&encoded_pub);
    return 0;
}

int authenticate_pace(PassyReader* reader) {
    const mbedtls_ecp_group_id gr_id = MBEDTLS_ECP_DP_BP256R1;
    mbedtls_ecp_group group;
    mbedtls_ecp_group_init(&group);
    int ret;

    ret = mbedtls_ecp_group_load(&group, gr_id);
    if(ret) {
        FURI_LOG_I(TAG, "error mbedtls_ecp_group_load. ret: %02x", ret);
        return -1;
    }

    mbedtls_mpi ephem_priv;
    mbedtls_ecp_point ephem_own_point;
    mbedtls_mpi_init(&ephem_priv);
    mbedtls_ecp_point_init(&ephem_own_point);

    ret = mbedtls_ecp_gen_keypair(&group, &ephem_priv, &ephem_own_point, f_rng, NULL);
    if(ret) {
        FURI_LOG_I(TAG, "error generating ephermal keypair. ret: %02x", ret);
        return -1;
    }

    mbedtls_mpi nonce;
    ret = get_nonce(reader, &nonce);
    if(ret) {
        FURI_LOG_I(TAG, "error decrypting nonce. ret: %d", ret);
        return -2;
    }

    return -55;
    mbedtls_ecp_point ephem_card_point = get_mapping_data(&ephem_own_point);

    mbedtls_ecp_point G_tilda = map_nonce(&nonce, &ephem_card_point, &ephem_priv, &group);

    uint8_t KSenc[KS_SIZE] = {0}, KSmac[KS_SIZE] = {0};
    if(derive_shared_secret(KSenc, KSmac, group, &G_tilda, &ephem_own_point, &ephem_card_point)) {
        FURI_LOG_I(TAG, "deriving shared error");
        return -3;
    }

    if(perform_mutual_auth(KSmac, &ephem_card_point, &group)) {
        FURI_LOG_I(TAG, "mutual auth fail");
        return -4;
    }

    return 0;
}

NfcCommand perform_pace_auth(PassyReader* reader) {
    int res = authenticate_pace(reader);
    if(res) {
        return NfcCommandStop;
    }
    return NfcCommandContinue;
}

void passy_read_big_file(
    PassyReader* passy_reader,
    uint8_t* result,
    unsigned int result_size,
    NfcCommand (*read_action)(uint8_t*, uint8_t, int)) {
    UNUSED(passy_reader);
    UNUSED(result);
    UNUSED(result_size);
    UNUSED(read_action);
    uint8_t temp_buff[60];

    NfcCommand res = NfcCommandContinue;
    int offset = 0;
    uint8_t* copy_region = result;
    do {
        res = read_action(temp_buff, sizeof(temp_buff), offset);
        copy_region =
            mempcpy(copy_region, temp_buff, sizeof(temp_buff)); // do not need to have 0x90000
        offset += sizeof(temp_buff);
        // FURI_LOG_D(TAG, "reading. %d, offset: %d, ", res, offset, display);
    } while(res == NfcCommandContinue && (offset + sizeof(temp_buff)) <= result_size);
}

NfcCommand passy_reader_pace_authenticate(PassyReader* passy_reader) {
    // reffer to SimaulatorCard.cpp and pages 10 and 19(29 in pdf) of 9303_p11_cons_en.pdf
    // example on page 103

    // idk i cannot decode this shit
    // 31820124300d060804007f00070202020201023012060a04007f000702020302020201020201413012060a04007f0007020203020202010302014a3012060a04007f0007020204020202010202010d3012060a04007f0007020204060202010202010d301b060b04007f000702020b010203300902010102010002010102014a301c060904007f000702020302300c060704007f0007010202010d020141301c060904007f000702020302300c060704007f0007010202010d02014a302a060804007f0007020206161e687474703a2f2f6273692e62756e642e64652f6369662f6e70612e786d6c303e060804007f000702020831323012060a04007f00070202030202020102020145301c060904007f000702020302300c060704007f0007010202010d020145
    // uint8_t buff[300];
    // memset(buff, 0, sizeof(buff));

    // //
    // NfcCommand ret = passy_reader_select_file(passy_reader, PassyReadDG14);
    // NfcCommand read_binary(uint8_t* buff, uint8_t size, int offset) {
    //     return passy_reader_read_binary(passy_reader, offset, size, buff);
    // }

    // passy_read_big_file(passy_reader, buff, sizeof(buff), read_binary);

    // passy_log_buffer(TAG, "whole_cardAccess", buff, sizeof(buff));
    // passy_log_buffer(TAG, "whole_cardAccess_part-2", buff + 128, sizeof(buff) - 128);
    // passy_log_buffer(TAG, "whole_cardAccess_part-3", buff + 128 + 128, sizeof(buff) - 128 - 128);

    //ret = passy_reader_select_file(passy_reader, EF_Dir);
    // memset(buff, 0, sizeof(buff));

    // passy_reader_read_binary(passy_reader, 0, sizeof(buff), buff);

    // section 4.4.3 and 9.2.3 for  0x80 data
    // command (p89) cla ins p1 p2 Le
    /*
Perform the Chip Access Procedure (see Section 4.2) and select the eMRTD Application; 
 9.2.11
  2.  Perform  Chip  Authentication  in  the  eMRTD  Application  (see  Section  6.2)  and  start  Passive 
Authentication (see Section 5.1); 
 
  3.  Perform Terminal Authentication (see below) in the eMRTD Application (see Section 7.1).
*/
    //BitBuffer* tx_buffer = passy_reader->tx_buffer;

    // *********************************
    // MSE:Set AT
    // *********************************

    // header
    // 00 22 C1A4
    // data size
    // data:
    // 80(tag) (size) (payload)
    // 83(tag) (size) (payload) ... 84 (?)
    // todo: size(payload) + 1 ? or size(payload) 0x80 payload?
    {
        uint8_t lc = 0x0F;
        uint8_t header[] = {0x00, 0x22, 0xC1, 0xA4, lc};
        uint8_t data[] = {
            0x80, // pace ecdh generic map aes128
            0x0A,
            0x04,
            0x00,
            0x7F,
            0x00,
            0x07,
            0x02,
            0x02,
            0x04,
            0x02,
            0x02,
            0x83, // pass
            0x01,
            0x03, // pin
            0x84, // ref to private key
            // 0x, // idk
            // 0x // idk
        };
        bit_buffer_free(passy_reader->tx_buffer);
        uint8_t payload[sizeof(header) + sizeof(data)];
        memcpy(payload, header, sizeof(header));
        memcpy(payload + sizeof(header), data, sizeof(data));
        BitBuffer* tx = bit_buffer_alloc(sizeof(payload));
        bit_buffer_copy_bytes(tx, payload, sizeof(payload));
        passy_reader->tx_buffer = tx;
        passy_reader_send(passy_reader);
    }

    // *********************************
    // GENERAL AUTHENTICATE
    // *********************************
    {
        uint8_t req[] = {0x10, 0x86, 0x00, 0x00, 0x02, 0x7C, 0x00, 0x00};
        bit_buffer_free(passy_reader->tx_buffer);

        const int response_size = 22;
        BitBuffer* rx = bit_buffer_alloc(response_size);
        BitBuffer* tx = bit_buffer_alloc(sizeof(req));
        bit_buffer_copy_bytes(tx, req, sizeof(req));
        passy_reader->tx_buffer = tx;
        passy_reader->rx_buffer = rx;
        passy_reader_send(passy_reader);
        // dne -- 0x6a80, invalid datafield
        // 7c12 8010 [930d5a88 a3053ac4 3eb60f66 3c3900f3] 9000
        // [] <- enc nonce
    }

    // *********************************
    // MAP NONCE
    // *********************************

    // p.107

    // todo, really need to read domain parameters, (or decode, idk fuck)
    // e.g. BrainpoolP256r1domain
    // upd, looks like shit from example should work, cause i have the same paceinfo (or whatever the shit)
    // 04007f00070202040202 020102 02010d
    // id                   ver    domain param (BrainpoolP256r1domain)
    // p.104

    //uint8_t secret_ref[] = {0x83, 0x01, 0x01}; // MRZ, 0x02 CAN (password)

    // // TODO: move into secure_messaging
    // SecureMessaging* secure_messaging = passy_reader->secure_messaging;
    // uint8_t S[32];
    // memset(S, 0, sizeof(S));
    // uint8_t eifd[32];
    // memcpy(S, secure_messaging->rndIFD, sizeof(secure_messaging->rndIFD));
    // memcpy(
    //     S + sizeof(secure_messaging->rndIFD),
    //     secure_messaging->rndICC,
    //     sizeof(secure_messaging->rndICC));
    // memcpy(
    //     S + sizeof(secure_messaging->rndIFD) + sizeof(secure_messaging->rndICC),
    //     secure_messaging->Kifd,
    //     sizeof(secure_messaging->Kifd));

    // uint8_t iv[8];
    // memset(iv, 0, sizeof(iv));
    // mbedtls_des3_context ctx;
    // mbedtls_des3_init(&ctx);
    // mbedtls_des3_set2key_enc(&ctx, secure_messaging->KENC);
    // mbedtls_des3_crypt_cbc(&ctx, MBEDTLS_DES_ENCRYPT, sizeof(S), iv, S, eifd);
    // mbedtls_des3_free(&ctx);

    // passy_log_buffer(TAG, "S", S, sizeof(S));
    // passy_log_buffer(TAG, "eifd", eifd, sizeof(eifd));

    // uint8_t mifd[8];
    // passy_mac(secure_messaging->KMAC, eifd, sizeof(eifd), mifd, false);
    // passy_log_buffer(TAG, "mifd", mifd, sizeof(mifd));

    // uint8_t authenticate_header[] = {0x00, 0x82, 0x00, 0x00};

    // bit_buffer_append_bytes(tx_buffer, authenticate_header, sizeof(authenticate_header));
    // bit_buffer_append_byte(tx_buffer, sizeof(eifd) + sizeof(mifd));
    // bit_buffer_append_bytes(tx_buffer, eifd, sizeof(eifd));
    // bit_buffer_append_bytes(tx_buffer, mifd, sizeof(mifd));
    // bit_buffer_append_byte(tx_buffer, 0); // Le

    // ret = passy_reader_send(passy_reader);
    // if(ret != NfcCommandContinue) {
    //     return ret;
    // }

    // const uint8_t* data = bit_buffer_get_data(passy_reader->rx_buffer);
    // size_t length = bit_buffer_get_size_bytes(passy_reader->rx_buffer);
    // const uint8_t* mac = data + length - 2 - 8;
    // uint8_t calculated_mac[8];
    // passy_mac(secure_messaging->KMAC, (uint8_t*)data, length - 8 - 2, calculated_mac, false);
    // if(memcmp(mac, calculated_mac, sizeof(calculated_mac)) != 0) {
    //     FURI_LOG_W(TAG, "Invalid MAC");
    //     return NfcCommandStop;
    // }

    // uint8_t decrypted[32];
    // do {
    //     uint8_t iv[8];
    //     memset(iv, 0, sizeof(iv));

    //     mbedtls_des3_context ctx;
    //     mbedtls_des3_init(&ctx);
    //     mbedtls_des3_set2key_dec(&ctx, secure_messaging->KENC);
    //     mbedtls_des3_crypt_cbc(&ctx, MBEDTLS_DES_DECRYPT, length - 2 - 8, iv, data, decrypted);
    //     mbedtls_des3_free(&ctx);
    // } while(false);

    // if(print_logs) {
    //     passy_log_buffer(TAG, "decrypted", decrypted, sizeof(decrypted));
    // }

    // uint8_t* rnd_icc = decrypted;
    // uint8_t* rnd_ifd = decrypted + 8;
    // uint8_t* Kicc = decrypted + 16;

    // if(memcmp(rnd_icc, secure_messaging->rndICC, sizeof(secure_messaging->rndICC)) != 0) {
    //     FURI_LOG_W(TAG, "Invalid rndICC");
    //     return NfcCommandStop;
    // }

    // memcpy(secure_messaging->Kicc, Kicc, sizeof(secure_messaging->Kicc));
    // memcpy(secure_messaging->SSC + 0, rnd_icc + 4, 4);
    // memcpy(secure_messaging->SSC + 4, rnd_ifd + 4, 4);

    return NfcCommandStop;
}
