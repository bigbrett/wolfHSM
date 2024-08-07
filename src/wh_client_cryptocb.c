/*
 * Copyright (C) 2024 wolfSSL Inc.
 *
 * This file is part of wolfHSM.
 *
 * wolfHSM is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfHSM is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with wolfHSM.  If not, see <http://www.gnu.org/licenses/>.
 */
/*
 * src/wh_cryptocb.c
 *
 */

#include <stdint.h>

#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_comm.h"
#include "wolfhsm/wh_packet.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_message.h"

#ifndef WOLFHSM_CFG_NO_CRYPTO

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "wolfssl/wolfcrypt/cryptocb.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/cmac.h"
#include "wolfssl/wolfcrypt/rsa.h"

#include "wolfhsm/wh_client_cryptocb.h"

#if defined(DEBUG_CRYPTOCB) || defined(DEBUG_CRYPTOCB_VERBOSE)
#include <stdio.h>
#endif

#ifdef DEBUG_CRYPTOCB_VERBOSE
static void _hexdump(const char* initial,uint8_t* ptr, size_t size)
{
    if(initial != NULL)
        printf("%s",initial);
    while(size > 0) {
        printf ("%02X ", *ptr);
        ptr++;
        size --;
    }
    printf("\n");
}
#endif

int wh_Client_CryptoCb(int devId, wc_CryptoInfo* info, void* inCtx)
{
    /* III When possible, return wolfCrypt-enumerated errors */
    int ret = CRYPTOCB_UNAVAILABLE;
    whClientContext* ctx = inCtx;
    whPacket* packet = NULL;
    uint16_t group = WH_MESSAGE_GROUP_CRYPTO;
    uint16_t action = WH_MESSAGE_ACTION_NONE;
    uint16_t dataSz = 0;

    if (    (devId == INVALID_DEVID) ||
            (info == NULL) ||
            (inCtx == NULL)) {
        return BAD_FUNC_ARG;
    }

    /* Get data pointer from the context to use as request/response storage */
    packet = (whPacket*)wh_CommClient_GetDataPtr(ctx->comm);
    if (packet == NULL) {
        return BAD_FUNC_ARG;
    }
    XMEMSET((uint8_t*)packet, 0, WOLFHSM_CFG_COMM_DATA_LEN);

    /* Based on the info type, process the request */
    switch (info->algo_type)
    {
    case WC_ALGO_TYPE_CIPHER:
        /* Set shared cipher request members */
        packet->cipherAnyReq.type = info->cipher.type;
        packet->cipherAnyReq.enc = info->cipher.enc;

        switch (info->cipher.type)
        {
#ifndef NO_AES
#ifdef HAVE_AES_CBC
        case WC_CIPHER_AES_CBC:
        {
            /* key, iv, in, and out are after fixed size fields */
            uint8_t* key = (uint8_t*)(&packet->cipherAesCbcReq + 1);
            uint8_t* out = (uint8_t*)(&packet->cipherAesCbcRes + 1);
            uint8_t* iv = key + info->cipher.aescbc.aes->keylen;
            uint8_t* in = iv + AES_IV_SIZE;
            uint16_t blocks = info->cipher.aescbc.sz / AES_BLOCK_SIZE;
            size_t last_offset = (blocks - 1) * AES_BLOCK_SIZE;
            uint8_t* ciphertext = NULL;
            dataSz =    sizeof(packet->cipherAesCbcReq) +
                        info->cipher.aescbc.aes->keylen +
                        AES_IV_SIZE +
                        info->cipher.aescbc.sz;

            /* III 0 size check is done in wolfCrypt */
            if(     (blocks == 0) ||
                    ((info->cipher.aescbc.sz % AES_BLOCK_SIZE) != 0) ) {
                /* CBC requires only full blocks */
                ret = BAD_LENGTH_E;
                break;
            }
            /* Is the request larger than a single message? */
            if (dataSz > WOLFHSM_CFG_COMM_DATA_LEN) {
                /* if we're using an HSM key return BAD_FUNC_ARG */
                if ((intptr_t)info->cipher.aescbc.aes->devCtx != 0) {
                    ret = BAD_FUNC_ARG;
                } else {
                    ret = BAD_LENGTH_E;
                }
                break;
            }

            /* Determine where ciphertext is for chaining */
            if(info->cipher.enc != 0) {
                ciphertext = out;
            } else {
                ciphertext = in;
            }

            /* Set AESCBC request members */
            packet->cipherAesCbcReq.keyLen = info->cipher.aescbc.aes->keylen;
            packet->cipherAesCbcReq.sz = info->cipher.aescbc.sz;
            XMEMCPY(iv, info->cipher.aescbc.aes->reg, AES_IV_SIZE);
            /* Set keyId from the AES context.  This may be WH_KEYID_INVALID */
            packet->cipherAesCbcReq.keyId =
                    WH_DEVCTX_TO_KEYID(info->cipher.aescbc.aes->devCtx);
            /* Set key data if reasonable */
            if (    (packet->cipherAesCbcReq.keyLen > 0) &&
                    (packet->cipherAesCbcReq.keyLen <=
                            sizeof(info->cipher.aescbc.aes->devKey))) {
                XMEMCPY(key, info->cipher.aescbc.aes->devKey,
                        info->cipher.aescbc.aes->keylen);
            }
            /* Set in */
            if (    (info->cipher.aescbc.in != NULL) &&
                    (info->cipher.aescbc.sz > 0)) {
                XMEMCPY(in, info->cipher.aescbc.in, info->cipher.aescbc.sz);
            }
            /* write request */
            ret = wh_Client_SendRequest(ctx, group,
                WC_ALGO_TYPE_CIPHER,
                WH_PACKET_STUB_SIZE + dataSz,
                (uint8_t*)packet);
#ifdef DEBUG_CRYPTOCB_VERBOSE
            printf("- Client sent AESCBC request. key:%p %d, in:%p %d, out:%p, enc:%d, ret:%d\n",
                    info->cipher.aescbc.aes->devKey, info->cipher.aescbc.aes->keylen,
                    info->cipher.aescbc.in, info->cipher.aescbc.sz,
                    info->cipher.aescbc.out, info->cipher.enc, ret);
            _hexdump("  In:", in, packet->cipherAesCbcReq.sz);
            _hexdump("  Key:", key, packet->cipherAesCbcReq.keyLen);
#endif /* DEBUG_CRYPTOCB */

            /* read response */
            if (ret == 0) {
                do {
                    ret = wh_Client_RecvResponse(ctx, &group, &action, &dataSz,
                        (uint8_t*)packet);
                } while (ret == WH_ERROR_NOTREADY);
            }

            if (ret == 0) {
                if (packet->rc != 0)
                    ret = packet->rc;
                else {
#ifdef DEBUG_CRYPTOCB_VERBOSE
                    _hexdump("  Out:", out, packet->cipherAesCbcRes.sz);
#endif /* DEBUG_CRYPTOCB */
                    /* copy the response out */
                    XMEMCPY(info->cipher.aescbc.out, out,
                        packet->cipherAesCbcRes.sz);
                    /* Update the IV with the last cipher text black */
                    XMEMCPY(info->cipher.aescbc.aes->reg,
                            ciphertext + last_offset,
                            AES_BLOCK_SIZE);
                }
            }
        } break;
#endif /* HAVE_AES_CBC */

#ifdef HAVE_AESGCM
        case WC_CIPHER_AES_GCM:
        {
            /* key, iv, in, authIn, and out are after fixed size fields */
            uint8_t* key = (uint8_t*)(&packet->cipherAesGcmReq + 1);
            uint8_t* out = (uint8_t*)(&packet->cipherAesGcmRes + 1);
            uint8_t* iv = key + info->cipher.aesgcm_enc.aes->keylen;
            uint8_t* in = iv + info->cipher.aesgcm_enc.ivSz;
            uint8_t* authIn = in + info->cipher.aesgcm_enc.sz;
            uint8_t* authTag = (info->cipher.enc == 0) ?
                    authIn + info->cipher.aesgcm_enc.authInSz :
                    out + info->cipher.aesgcm_enc.sz;
            dataSz = sizeof(packet->cipherAesGcmReq) +
                info->cipher.aesgcm_enc.aes->keylen +
                info->cipher.aesgcm_enc.ivSz + info->cipher.aesgcm_enc.sz +
                info->cipher.aesgcm_enc.authInSz +
                info->cipher.aesgcm_enc.authTagSz;

            if (dataSz > WOLFHSM_CFG_COMM_DATA_LEN) {
                /* if we're using an HSM key return BAD_FUNC_ARG */
                if (info->cipher.aesgcm_enc.aes->devCtx != NULL) {
                    ret = BAD_FUNC_ARG;
                } else {
                    ret = CRYPTOCB_UNAVAILABLE;
                }
                break;
            }

            /* set keyLen */
            packet->cipherAesGcmReq.keyLen =
                info->cipher.aesgcm_enc.aes->keylen;
            /* set metadata */
            packet->cipherAesGcmReq.sz = info->cipher.aesgcm_enc.sz;
            packet->cipherAesGcmReq.ivSz = info->cipher.aesgcm_enc.ivSz;
            packet->cipherAesGcmReq.authInSz = info->cipher.aesgcm_enc.authInSz;
            packet->cipherAesGcmReq.authTagSz =
                info->cipher.aesgcm_enc.authTagSz;
            packet->cipherAesGcmReq.keyId =
                (intptr_t)(info->cipher.aescbc.aes->devCtx);
            /* set key */
            XMEMCPY(key, info->cipher.aesgcm_enc.aes->devKey,
                info->cipher.aesgcm_enc.aes->keylen);
            /* write the bulk data */
            XMEMCPY(iv, info->cipher.aesgcm_enc.iv,
                info->cipher.aesgcm_enc.ivSz);
            XMEMCPY(in, info->cipher.aesgcm_enc.in, info->cipher.aesgcm_enc.sz);
            XMEMCPY(authIn, info->cipher.aesgcm_enc.authIn,
                info->cipher.aesgcm_enc.authInSz);
            /* set auth tag by direction */
            if (info->cipher.enc == 0) {
                XMEMCPY(authTag, info->cipher.aesgcm_dec.authTag,
                    info->cipher.aesgcm_enc.authTagSz);
            }
            /* write request */
            ret = wh_Client_SendRequest(ctx, group,
                WC_ALGO_TYPE_CIPHER,
                WH_PACKET_STUB_SIZE + dataSz,
                (uint8_t*)packet);
            /* read response */
            if (ret == 0) {
                do {
                    ret = wh_Client_RecvResponse(ctx, &group, &action, &dataSz,
                        (uint8_t*)packet);
                } while (ret == WH_ERROR_NOTREADY);
            }
            if (ret == 0) {
                if (packet->rc != 0)
                    ret = packet->rc;
                else {
                    /* copy the response out */
                    XMEMCPY(info->cipher.aesgcm_enc.out, out,
                        packet->cipherAesGcmRes.sz);
                    /* write the authTag if applicable */
                    if (info->cipher.enc != 0) {
                        XMEMCPY(info->cipher.aesgcm_enc.authTag, authTag,
                            packet->cipherAesGcmRes.authTagSz);
                    }
                }
            }
        } break;
#endif /* HAVE_AESGCM */
#endif /* !NO_AES */

        default:
            ret = CRYPTOCB_UNAVAILABLE;
            break;
        }
        break;

    case WC_ALGO_TYPE_PK:
        /* set type */
        packet->pkAnyReq.type = info->pk.type;
        switch (info->pk.type)
        {
#ifndef NO_RSA
#ifdef WOLFSSL_KEY_GEN
        case WC_PK_TYPE_RSA_KEYGEN:
        {
            /* set size */
            packet->pkRsakgReq.size = info->pk.rsakg.size;
            /* set e */
            packet->pkRsakgReq.e = info->pk.rsakg.e;
            /* write request */
            ret = wh_Client_SendRequest(ctx, group,
                WC_ALGO_TYPE_PK,
                WH_PACKET_STUB_SIZE + sizeof(packet->pkRsakgReq),
                (uint8_t*)packet);
#ifdef DEBUG_CRYPTOCB_VERBOSE
            printf("RSA KeyGen Req sent:size:%u, e:%u, ret:%d\n",
                    packet->pkRsakgReq.size, packet->pkRsakgReq.e, ret);
#endif
            if (ret == 0) {
                do {
                    ret = wh_Client_RecvResponse(ctx, &group, &action, &dataSz,
                        (uint8_t*)packet);
                } while (ret == WH_ERROR_NOTREADY);
            }
#ifdef DEBUG_CRYPTOCB_VERBOSE
            printf("RSA KeyGen Res recv:keyid:%u, rc:%d, ret:%d\n",
                    packet->pkRsakgRes.keyId, packet->rc, ret);
#endif
            if (ret == 0) {
                if (packet->rc != 0)
                    ret = packet->rc;
                else {
                    whKeyId keyId = packet->pkRsakgRes.keyId;
                    info->pk.rsakg.key->devCtx = WH_KEYID_TO_DEVCTX(keyId);

                    if (info->pk.rsakg.key != NULL) {
                        /* DER cannot be larger than MTU */
                        byte keyDer[WOLFHSM_CFG_COMM_DATA_LEN] = {0};
                        uint32_t derSize = sizeof(keyDer);
                        word32 idx = 0;
                        uint8_t keyLabel[WH_NVM_LABEL_LEN] = {0};

                        /* Now export the key and update the RSA Key structure */
                        ret = wh_Client_KeyExport(ctx,keyId,
                                keyLabel, sizeof(keyLabel),
                                keyDer, &derSize);
#ifdef DEBUG_CRYPTOCB_VERBOSE
                        printf("-RSA Keygen Der size:%u\n", derSize);
#endif
                        if (ret == 0) {
                            /* Update the RSA key structure */
                            ret = wc_RsaPrivateKeyDecode(
                                    keyDer, &idx,
                                    info->pk.rsakg.key,
                                    derSize);
                        }
                    }
                }
            }
        } break;
#endif  /* WOLFSSL_KEY_GEN */

        case WC_PK_TYPE_RSA:
        {
            whKeyId cacheKeyId = WH_KEYID_ERASED;
            byte keyDer[5000] = {0};  /* Estimated size of a 4096 keyfile */
            int derSize = 0;
            char keyLabel[] = "ClientCbTemp";

            /* in and out are after the fixed size fields */
            uint8_t* in = (uint8_t*)(&packet->pkRsaReq + 1);
            uint8_t* out = (uint8_t*)(&packet->pkRsaRes + 1);
            dataSz = WH_PACKET_STUB_SIZE + sizeof(packet->pkRsaReq)
                + info->pk.rsa.inLen;

            /* can't fallback to software since the key is on the HSM */
            if (dataSz > WOLFHSM_CFG_COMM_DATA_LEN) {
                ret = BAD_FUNC_ARG;
                break;
            }

            /* set keyId */
            packet->pkRsaReq.keyId = WH_DEVCTX_TO_KEYID(info->pk.rsa.key->devCtx);
            if (packet->pkRsaReq.keyId == WH_KEYID_ERASED) {
                /* Must import the key to the server */
                /* Convert RSA key to DER format */
                ret = derSize = wc_RsaKeyToDer(info->pk.rsa.key, keyDer, sizeof(keyDer));
                if(derSize >= 0) {
                    /* Cache the key and get the keyID */
                    /* WWW This is likely recursive so assume the packet will be
                     *     trashed by the time this returns */
                    ret = wh_Client_KeyCache(ctx, 0, (uint8_t*)keyLabel,
                        sizeof(keyLabel), keyDer, derSize, &cacheKeyId);
                    packet->pkRsaReq.keyId = cacheKeyId;
                }
            }
#ifdef DEBUG_CRYPTOCB_VERBOSE
            printf("RSA keyId:%u cacheKeyId:%u derSize:%u\n",
                    packet->pkRsaReq.keyId,
                    cacheKeyId,
                    derSize);
#endif
            /* set type */
            packet->pkRsaReq.opType = info->pk.rsa.type;
#ifdef DEBUG_CRYPTOCB_VERBOSE
            printf("RSA optype:%u\n",packet->pkRsaReq.opType);
#endif
            /* set inLen */
            packet->pkRsaReq.inLen = info->pk.rsa.inLen;
            /* set outLen */
            packet->pkRsaReq.outLen = *info->pk.rsa.outLen;
            /* set in */
            XMEMCPY(in, info->pk.rsa.in, info->pk.rsa.inLen);
            /* write request */
            ret = wh_Client_SendRequest(ctx, group, WC_ALGO_TYPE_PK, dataSz,
                (uint8_t*)packet);
#ifdef DEBUG_CRYPTOCB_VERBOSE
            printf("RSA req sent. opType:%u inLen:%d keyId:%u outLen:%u type:%u\n",
                    packet->pkRsaReq.opType,
                    packet->pkRsaReq.inLen,
                    packet->pkRsaReq.keyId,
                    packet->pkRsaReq.outLen,
                    packet->pkRsaReq.type);
#endif
            /* read response */
            if (ret == 0) {
                do {
                    ret = wh_Client_RecvResponse(ctx, &group, &action, &dataSz,
                        (uint8_t*)packet);
                } while (ret == WH_ERROR_NOTREADY);
            }
#ifdef DEBUG_CRYPTOCB_VERBOSE
            printf("RSA resp packet recv. ret:%d rc:%d\n", ret, packet->rc);
#endif
            if (ret == 0) {
                if (packet->rc != 0)
                    ret = packet->rc;
                else {
                    /* read outLen */
                    *info->pk.rsa.outLen = packet->pkRsaRes.outLen;
                    /* read out */
                    XMEMCPY(info->pk.rsa.out, out, packet->pkRsaRes.outLen);
                }
            }
            if (cacheKeyId != WH_KEYID_ERASED) {
                /* Evict the cached key */
                ret = wh_Client_KeyEvict(ctx, cacheKeyId);
            }
        } break;

        case WC_PK_TYPE_RSA_GET_SIZE:
        {
            /* set keyId */
            packet->pkRsaGetSizeReq.keyId =
                (intptr_t)(info->pk.rsa_get_size.key->devCtx);
            /* write request */
            ret = wh_Client_SendRequest(ctx, group,
                WC_ALGO_TYPE_PK,
                WH_PACKET_STUB_SIZE + sizeof(packet->pkRsaGetSizeReq),
                (uint8_t*)packet);
            /* read response */
            if (ret == 0) {
                do {
                    ret = wh_Client_RecvResponse(ctx, &group, &action, &dataSz,
                        (uint8_t*)packet);
                } while (ret == WH_ERROR_NOTREADY);
            }
            if (ret == 0) {
                if (packet->rc != 0)
                    ret = packet->rc;
                else {
                    /* read outLen */
                    *info->pk.rsa_get_size.keySize =
                        packet->pkRsaGetSizeRes.keySize;
                }
            }
        } break;

#endif /* !NO_RSA */

#ifdef HAVE_ECC
        case WC_PK_TYPE_EC_KEYGEN:
        {
            /* set key size */
            packet->pkEckgReq.sz = info->pk.eckg.size;
            /* set curveId */
            packet->pkEckgReq.curveId = info->pk.eckg.curveId;
            /* write request */
            ret = wh_Client_SendRequest(ctx, group,
                WC_ALGO_TYPE_PK,
                WH_PACKET_STUB_SIZE + sizeof(packet->pkEckgReq),
                (uint8_t*)packet);
            /* read response */
            if (ret == 0) {
                do {
                    ret = wh_Client_RecvResponse(ctx, &group, &action, &dataSz,
                        (uint8_t*)packet);
                } while (ret == WH_ERROR_NOTREADY);
            }
            if (ret == 0) {
                if (packet->rc != 0)
                    ret = packet->rc;
                else {
                    /* read keyId */
                    info->pk.eckg.key->devCtx =
                        (void*)((intptr_t)packet->pkEckgRes.keyId);
                }
            }
        } break;

        case WC_PK_TYPE_ECDH:
        {
            /* out is after the fixed size fields */
            uint8_t* out = (uint8_t*)(&packet->pkEcdhRes + 1);

            /* set ids */
            packet->pkEcdhReq.privateKeyId =
                (intptr_t)info->pk.ecdh.private_key->devCtx;
            packet->pkEcdhReq.publicKeyId =
                (intptr_t)info->pk.ecdh.public_key->devCtx;
            /* set curveId */
            packet->pkEcdhReq.curveId =
                wc_ecc_get_curve_id(info->pk.ecdh.private_key->idx);
            /* write request */
            ret = wh_Client_SendRequest(ctx, group,
                WC_ALGO_TYPE_PK,
                WH_PACKET_STUB_SIZE + sizeof(packet->pkEcdhReq),
                (uint8_t*)packet);
            /* read response */
            if (ret == 0) {
                do {
                    ret = wh_Client_RecvResponse(ctx, &group, &action, &dataSz,
                        (uint8_t*)packet);
                } while (ret == WH_ERROR_NOTREADY);
            }
            if (ret == 0) {
                if (packet->rc != 0)
                    ret = packet->rc;
                else {
                    /* read out */
                    XMEMCPY(info->pk.ecdh.out, out, packet->pkEcdhRes.sz);
                    *info->pk.ecdh.outlen = packet->pkEcdhRes.sz;
                }
            }
        } break;

        case WC_PK_TYPE_ECDSA_SIGN:
        {
            /* in and out are after the fixed size fields */
            uint8_t* in = (uint8_t*)(&packet->pkEccSignReq + 1);
            uint8_t* out = (uint8_t*)(&packet->pkEccSignRes + 1);
            dataSz = WH_PACKET_STUB_SIZE + sizeof(packet->pkEccSignReq) +
                info->pk.eccsign.inlen;

            /* can't fallback to software since the key is on the HSM */
            if (dataSz > WOLFHSM_CFG_COMM_DATA_LEN) {
                ret = BAD_FUNC_ARG;
                break;
            }

            /* set keyId */
            packet->pkEccSignReq.keyId = (intptr_t)info->pk.eccsign.key->devCtx;
            /* set curveId */
            packet->pkEccSignReq.curveId =
                wc_ecc_get_curve_id(info->pk.eccsign.key->idx);
            /* set sz */
            packet->pkEccSignReq.sz = info->pk.eccsign.inlen;
            /* set in */
            XMEMCPY(in, info->pk.eccsign.in, info->pk.eccsign.inlen);
            /* write request */
            ret = wh_Client_SendRequest(ctx, group, WC_ALGO_TYPE_PK, dataSz,
                (uint8_t*)packet);
            /* read response */
            if (ret == 0) {
                do {
                    ret = wh_Client_RecvResponse(ctx, &group, &action, &dataSz,
                        (uint8_t*)packet);
                } while (ret == WH_ERROR_NOTREADY);
            }
            if (ret == 0) {
                if (packet->rc != 0)
                    ret = packet->rc;
                else {
                    /* check outlen and read out */
                    if (*info->pk.eccsign.outlen < packet->pkEccSignRes.sz) {
                        ret = BUFFER_E;
                    }
                    else {
                        *info->pk.eccsign.outlen = packet->pkEccSignRes.sz;
                        XMEMCPY(info->pk.eccsign.out, out,
                            packet->pkEccSignRes.sz);
                    }
                }
            }
        } break;

        case WC_PK_TYPE_ECDSA_VERIFY:
        {
            /* sig and hash are after the fixed size fields */
            uint8_t* sig = (uint8_t*)(&packet->pkEccVerifyReq + 1);
            uint8_t* hash = (uint8_t*)(&packet->pkEccVerifyReq + 1) +
                info->pk.eccverify.siglen;
            dataSz = WH_PACKET_STUB_SIZE + sizeof(packet->pkEccVerifyReq) +
                info->pk.eccverify.siglen + info->pk.eccverify.hashlen;

            /* can't fallback to software since the key is on the HSM */
            if (dataSz > WOLFHSM_CFG_COMM_DATA_LEN) {
                ret = BAD_FUNC_ARG;
                break;
            }

            /* set keyId */
            packet->pkEccVerifyReq.keyId =
                (intptr_t)info->pk.eccverify.key->devCtx;
            /* set curveId */
            packet->pkEccVerifyReq.curveId =
                wc_ecc_get_curve_id(info->pk.eccverify.key->idx);
            /* set sig and hash sz */
            packet->pkEccVerifyReq.sigSz = info->pk.eccverify.siglen;
            packet->pkEccVerifyReq.hashSz = info->pk.eccverify.hashlen;
            /* copy sig and hash */
            XMEMCPY(sig, info->pk.eccverify.sig, info->pk.eccverify.siglen);
            XMEMCPY(hash, info->pk.eccverify.hash, info->pk.eccverify.hashlen);
            /* write request */
            ret = wh_Client_SendRequest(ctx, group, WC_ALGO_TYPE_PK, dataSz,
                (uint8_t*)packet);
            /* read response */
            if (ret == 0) {
                do {
                    ret = wh_Client_RecvResponse(ctx, &group, &action, &dataSz,
                        (uint8_t*)packet);
                } while (ret == WH_ERROR_NOTREADY);
            }
            if (ret == 0) {
                if (packet->rc != 0)
                    ret = packet->rc;
                else {
                    /* read out */
                    *info->pk.eccverify.res = packet->pkEccVerifyRes.res;
                }
            }
        } break;

        case WC_PK_TYPE_EC_CHECK_PRIV_KEY:
        {
            /* set keyId */
            packet->pkEccCheckReq.keyId =
                (intptr_t)(info->pk.ecc_check.key->devCtx);
            /* set curveId */
            packet->pkEccCheckReq.curveId =
                wc_ecc_get_curve_id(info->pk.eccverify.key->idx);
            /* write request */
            ret = wh_Client_SendRequest(ctx, group,
                WC_ALGO_TYPE_PK,
                WH_PACKET_STUB_SIZE + sizeof(packet->pkEccCheckReq),
                (uint8_t*)packet);
            /* read response */
            if (ret == 0) {
                do {
                    ret = wh_Client_RecvResponse(ctx, &group, &action, &dataSz,
                        (uint8_t*)packet);
                } while (ret == WH_ERROR_NOTREADY);
            }
            if (ret == 0) {
                if (packet->rc != 0)
                    ret = packet->rc;
            }
        } break;

        #endif /* HAVE_ECC */
#ifdef HAVE_CURVE25519
        case WC_PK_TYPE_CURVE25519_KEYGEN:
        {
            packet->pkCurve25519kgReq.sz = info->pk.curve25519kg.size;
            /* write request */
            ret = wh_Client_SendRequest(ctx, group,
                WC_ALGO_TYPE_PK,
                WH_PACKET_STUB_SIZE + sizeof(packet->pkCurve25519kgReq),
                (uint8_t*)packet);
            if (ret == 0) {
                do {
                    ret = wh_Client_RecvResponse(ctx, &group, &action, &dataSz,
                        (uint8_t*)packet);
                } while (ret == WH_ERROR_NOTREADY);
            }
            if (ret == 0) {
                if (packet->rc != 0)
                    ret = packet->rc;
                /* read out */
                else {
                    info->pk.curve25519kg.key->devCtx =
                        (void*)((intptr_t)packet->pkCurve25519kgRes.keyId);
                    /* set metadata */
                    info->pk.curve25519kg.key->pubSet = 1;
                    info->pk.curve25519kg.key->privSet = 1;
                }
            }
        } break;

        case WC_PK_TYPE_CURVE25519:
        {
            uint8_t* out = (uint8_t*)(&packet->pkCurve25519Res + 1);

            packet->pkCurve25519Req.privateKeyId =
                (intptr_t)(info->pk.curve25519.private_key->devCtx);
            packet->pkCurve25519Req.publicKeyId =
                (intptr_t)(info->pk.curve25519.public_key->devCtx);
            packet->pkCurve25519Req.endian = info->pk.curve25519.endian;
            /* write request */
            ret = wh_Client_SendRequest(ctx, group,
                WC_ALGO_TYPE_PK,
                WH_PACKET_STUB_SIZE + sizeof(packet->pkCurve25519Req),
                (uint8_t*)packet);
            if (ret == 0) {
                do {
                    ret = wh_Client_RecvResponse(ctx, &group, &action, &dataSz,
                        (uint8_t*)packet);
                } while (ret == WH_ERROR_NOTREADY);
            }
            if (ret == 0) {
                if (packet->rc != 0)
                    ret = packet->rc;
                /* read out */
                else {
                    XMEMCPY(info->pk.curve25519.out, out,
                        packet->pkCurve25519Res.sz);
                }
            }
        } break;

#endif /* HAVE_CURVE25519 */

        case WC_PK_TYPE_NONE:
        default:
            ret = CRYPTOCB_UNAVAILABLE;
            break;
        }
        break;

#ifndef WC_NO_RNG
    case WC_ALGO_TYPE_RNG:
    {
        /* out is after the fixed size fields */
        uint8_t* out = (uint8_t*)(&packet->rngRes + 1);

        /* set sz */
        packet->rngReq.sz = info->rng.sz;
        /* write request */
        ret = wh_Client_SendRequest(ctx, group, WC_ALGO_TYPE_RNG,
            WH_PACKET_STUB_SIZE + sizeof(packet->rngReq),(uint8_t*)packet);
        if (ret == 0) {
            do {
                ret = wh_Client_RecvResponse(ctx, &group, &action, &dataSz,
                    (uint8_t*)packet);
            } while (ret == WH_ERROR_NOTREADY);
        }
        if (ret == 0) {
            if (packet->rc != 0)
                ret = packet->rc;
            /* read out */
            else
                XMEMCPY(info->rng.out, out, packet->rngRes.sz);
        }
    } break;
#endif /* !WC_NO_RNG */

#ifdef WOLFSSL_CMAC
    case WC_ALGO_TYPE_CMAC:
    {
        /* in, key and out are after the fixed size fields */
        uint8_t* in = (uint8_t*)(&packet->cmacReq + 1);
        uint8_t* key = in + info->cmac.inSz;
        uint8_t* out = (uint8_t*)(&packet->cmacRes + 1);
        dataSz = WH_PACKET_STUB_SIZE + sizeof(packet->cmacReq) +
            info->cmac.inSz + info->cmac.keySz;

        if (dataSz > WOLFHSM_CFG_COMM_DATA_LEN) {
            /* if we're using an HSM key return BAD_FUNC_ARG */
            if (info->cmac.cmac->devCtx != NULL) {
                ret = BAD_FUNC_ARG;
            } else {
                ret = CRYPTOCB_UNAVAILABLE;
            }
            break;
        }
        /* Return success for init call with NULL params */
        if (    (info->cmac.in == NULL) &&
                (info->cmac.key == NULL) &&
                (info->cmac.out == NULL)) {
            ret = 0;
            break;
        }

        packet->cmacReq.type = info->cmac.type;
        packet->cmacReq.keyId = (intptr_t)info->cmac.cmac->devCtx;
        /* multiple modes are possible so we need to set zero size if buffers
         * are NULL */
        if (info->cmac.in != NULL) {
            packet->cmacReq.inSz = info->cmac.inSz;
            XMEMCPY(in, info->cmac.in, info->cmac.inSz);
        }
        else
            packet->cmacReq.inSz = 0;
        if (info->cmac.key != NULL) {
            packet->cmacReq.keySz = info->cmac.keySz;
            XMEMCPY(key, info->cmac.key, info->cmac.keySz);
        }
        else
            packet->cmacReq.keySz = 0;
        if (info->cmac.out != NULL)
            packet->cmacReq.outSz = *(info->cmac.outSz);
        else
            packet->cmacReq.outSz = 0;
        /* write request */
        ret = wh_Client_SendRequest(ctx, group, WC_ALGO_TYPE_CMAC,
            WH_PACKET_STUB_SIZE + sizeof(packet->cmacReq) +
            packet->cmacReq.inSz + packet->cmacReq.keySz, (uint8_t*)packet);
        if (ret == 0) {
            /* if the client marked they may want to cancel, handle the 
             * response in a seperate call */
            if (ctx->cancelable)
                break;
            do {
                ret = wh_Client_RecvResponse(ctx, &group, &action, &dataSz,
                    (uint8_t*)packet);
            } while (ret == WH_ERROR_NOTREADY);
        }
        if (ret == 0) {
            if (packet->rc != 0)
                ret = packet->rc;
            /* read keyId and out */
            else {
                if (info->cmac.key != NULL) {
                    info->cmac.cmac->devCtx =
                        (void*)((intptr_t)packet->cmacRes.keyId);
                }
                if (info->cmac.out != NULL) {
                    XMEMCPY(info->cmac.out, out, packet->cmacRes.outSz);
                    *(info->cmac.outSz) = packet->cmacRes.outSz;
                }
            }
        }
    } break;

#endif /* WOLFSSL_CMAC */
    case WC_ALGO_TYPE_NONE:
    default:
        ret = CRYPTOCB_UNAVAILABLE;
        break;
    }

#ifdef DEBUG_CRYPTOCB
    if (ret == CRYPTOCB_UNAVAILABLE) {
        printf("X whClientCb not implemented: algo->type:%d\n", info->algo_type);
    } else {
        printf("- whClientCb ret:%d algo->type:%d\n", ret, info->algo_type);
    }
    wc_CryptoCb_InfoString(info);
#endif /* DEBUG_CRYPTOCB */
    return ret;
}

#endif /* !WOLFHSM_CFG_NO_CRYPTO */
