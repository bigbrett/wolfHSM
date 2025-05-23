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
#ifndef WH_TEST_CHECK_STRUCT_PADDING_C_
#define WH_TEST_CHECK_STRUCT_PADDING_C_

#include "wolfhsm/wh_settings.h"

/* For each included file, define an instance of every struct for which we want
 * to check padding. Then, when this file is compiled with -Wpadded it will
 * generate an error if padding is wrong */


#include "wolfhsm/wh_message_comm.h"
whMessageComm_ErrorResponse whMessageComm_ErrorResponse_test;
whMessageCommInitRequest    whMessageCommInitRequest_test;
whMessageCommInitResponse   whMessageCommInitResponse_test;
whMessageCommInfoResponse   whMessageCommInfoResponse_test;

#include "wolfhsm/wh_message_customcb.h"
whMessageCustomCb_Request  whMessageCustomCb_Request_test;
whMessageCustomCb_Response whMessageCustomCb_Response_test;

#include "wolfhsm/wh_message_nvm.h"
whMessageNvm_SimpleResponse        whMessageNvm_SimpleResponse_test;
whMessageNvm_InitRequest           whMessageNvm_InitRequest_test;
whMessageNvm_InitResponse          whMessageNvm_InitResponse_test;
whMessageNvm_GetAvailableResponse  whMessageNvm_GetAvailableResponse_test;
whMessageNvm_AddObjectRequest      whMessageNvm_AddObjectRequest_test;
whMessageNvm_ListRequest           whMessageNvm_ListRequest_test;
whMessageNvm_ListResponse          whMessageNvm_ListResponse_test;
whMessageNvm_GetMetadataRequest    whMessageNvm_GetMetadataRequest_test;
whMessageNvm_GetMetadataResponse   whMessageNvm_GetMetadataResponse_test;
whMessageNvm_DestroyObjectsRequest whMessageNvm_DestroyObjectsRequest_test;
whMessageNvm_ReadRequest           whMessageNvm_ReadRequest_test;
whMessageNvm_ReadResponse          whMessageNvm_ReadResponse_test;

#if defined(WOLFHSM_CFG_DMA) && WH_DMA_IS_32BIT
whMessageNvm_AddObjectDma32Request whMessageNvm_AddObjectDma32Request_test;
whMessageNvm_ReadDma32Request      whMessageNvm_ReadDma32Request_test;
#elif defined(WOLFHSM_CFG_DMA) && WH_DMA_IS_64BIT
whMessageNvm_AddObjectDma64Request whMessageNvm_AddObjectDma64Request_test;
whMessageNvm_ReadDma64Request      whMessageNvm_ReadDma64Request_test;
#endif

#include "wolfhsm/wh_packet.h"
whPacket whPacket_test;
/* Test every variant of the nested union */
wh_Packet_version_exchange      versionExchange;
wh_Packet_key_cache_req         keyCacheReq;
wh_Packet_key_evict_req         keyEvictReq;
wh_Packet_key_commit_req        keyCommitReq;
wh_Packet_key_export_req        keyExportReq;
wh_Packet_key_erase_req         keyEraseReq;
wh_Packet_counter_init_req      counterInitReq;
wh_Packet_counter_increment_req counterIncrementReq;
wh_Packet_counter_read_req      counterReadReq;
wh_Packet_counter_destroy_req   counterDestroyReq;
wh_Packet_key_cache_res         keyCacheRes;
wh_Packet_key_evict_res         keyEvictRes;
wh_Packet_key_commit_res        keyCommitRes;
wh_Packet_key_export_res        keyExportRes;
wh_Packet_key_erase_res         keyEraseRes;
wh_Packet_counter_init_res      counterInitRes;
wh_Packet_counter_increment_res counterIncrementRes;
wh_Packet_counter_read_res      counterReadRes;

#if defined(WOLFHSM_CFG_DMA) && WH_DMA_IS_32BIT
wh_Packet_key_cache_Dma32_req  keyCacheDma32Req;
wh_Packet_key_cache_Dma32_res  keyCacheDma32Res;
wh_Packet_key_export_Dma32_req keyExportDma32Req;
wh_Packet_key_export_Dma32_res keyExportDma32Res;
#elif defined(WOLFHSM_CFG_DMA) && WH_DMA_IS_64BIT
wh_Packet_key_cache_Dma64_req      keyCacheDma64Req;
wh_Packet_key_cache_Dma64_res      keyCacheDma64Res;
wh_Packet_key_export_Dma64_req     keyExportDma64Req;
wh_Packet_key_export_Dma64_res     keyExportDma64Res;
#endif

#ifndef WOLFHSM_CFG_NO_CRYPTO
wh_Packet_cipher_any_req      cipherAnyReq;
wh_Packet_cipher_aescbc_req   cipherAesCbcReq;
wh_Packet_cipher_aesgcm_req   cipherAesGcmReq;
wh_Packet_pk_any_req          pkAnyReq;
wh_Packet_pk_rsakg_req        pkRsakgReq;
wh_Packet_pk_rsa_req          pkRsaReq;
wh_Packet_pk_rsa_get_size_req pkRsaGetSizeReq;
wh_Packet_pk_eckg_req         pkEckgReq;
wh_Packet_pk_ecdh_req         pkEcdhReq;
wh_Packet_pk_ecc_sign_req     pkEccSignReq;
wh_Packet_pk_ecc_verify_req   pkEccVerifyReq;
wh_Packet_pk_ecc_check_req    pkEccCheckReq;
wh_Packet_pk_curve25519kg_req pkCurve25519kgReq;
wh_Packet_pk_curve25519kg_res pkCurve25519kgRes;
wh_Packet_pk_curve25519_req   pkCurve25519Req;
wh_Packet_pk_curve25519_res   pkCurve25519Res;
wh_Packet_rng_req             rngReq;
wh_Packet_cmac_req            cmacReq;
wh_Packet_cipher_aescbc_res   cipherAesCbcRes;
wh_Packet_cipher_aesgcm_res   cipherAesGcmRes;
wh_Packet_pk_rsakg_res        pkRsakgRes;
wh_Packet_pk_rsa_res          pkRsaRes;
wh_Packet_pk_rsa_get_size_res pkRsaGetSizeRes;
wh_Packet_pk_eckg_res         pkEckgRes;
wh_Packet_pk_ecdh_res         pkEcdhRes;
wh_Packet_pk_ecc_sign_res     pkEccSignRes;
wh_Packet_pk_ecc_verify_res   pkEccVerifyRes;
wh_Packet_pk_ecc_check_res    pkEccCheckRes;
wh_Packet_rng_res             rngRes;
wh_Packet_cmac_res            cmacRes;
wh_Packet_hash_any_req        hashAnyReq;
wh_Packet_hash_sha256_req     hashSha256Req;
wh_Packet_hash_sha256_res     hashSha256Res;

/* DMA structs */
#if defined(WOLFHSM_CFG_DMA) && WH_DMA_IS_32BIT
wh_Packet_hash_sha256_Dma32_req     hashSha256Dma32Req;
wh_Packet_hash_sha256_Dma32_res     hashSha256Dma32Res;
wh_Packet_pq_mldsa_keygen_Dma32_req pqMldsaKeygenDma32Req;
wh_Packet_pq_mldsa_Dma32_res        pqMldsaDma32Res;
wh_Packet_pq_mldsa_sign_Dma32_req   pqMldsaSignDma32Req;
wh_Packet_pq_mldsa_sign_Dma32_res   pqMldsaSignDma32Res;
wh_Packet_pq_mldsa_verify_Dma32_req pqMldsaVerifyDma32Req;
wh_Packet_pq_mldsa_verify_Dma32_res pqMldsaVerifyDma32Res;
wh_Packet_cmac_Dma32_req            cmacDma32Req;
wh_Packet_cmac_Dma32_res            cmacDma32Res;
#elif defined(WOLFHSM_CFG_DMA) && WH_DMA_IS_64BIT
wh_Packet_hash_sha256_Dma64_req     hashSha256Dma64Req;
wh_Packet_hash_sha256_Dma64_res     hashSha256Dma64Res;
wh_Packet_pq_mldsa_keygen_Dma64_req pqMldsaKeygenDma64Req;
wh_Packet_pq_mldsa_Dma64_res        pqMldsaDma64Res;
wh_Packet_pq_mldsa_sign_Dma64_req   pqMldsaSignDma64Req;
wh_Packet_pq_mldsa_sign_Dma64_res   pqMldsaSignDma64Res;
wh_Packet_pq_mldsa_verify_Dma64_req pqMldsaVerifyDma64Req;
wh_Packet_pq_mldsa_verify_Dma64_res pqMldsaVerifyDma64Res;
wh_Packet_cmac_Dma64_req            cmacDma64Req;
wh_Packet_cmac_Dma64_res            cmacDma64Res;
#endif

#endif /* !WOLFHSM_CFG_NO_CRYPTO */

#ifdef WOLFHSM_CFG_SHE_EXTENSION
wh_Packet_she_set_uid_req            sheSetUidReq;
wh_Packet_she_secure_boot_init_req   sheSecureBootInitReq;
wh_Packet_she_secure_boot_init_res   sheSecureBootInitRes;
wh_Packet_she_secure_boot_update_req sheSecureBootUpdateReq;
wh_Packet_she_secure_boot_update_res sheSecureBootUpdateRes;
wh_Packet_she_secure_boot_finish_res sheSecureBootFinishRes;
wh_Packet_she_get_status_res         sheGetStatusRes;
wh_Packet_she_load_key_req           sheLoadKeyReq;
wh_Packet_she_load_key_res           sheLoadKeyRes;
wh_Packet_she_load_plain_key_req     sheLoadPlainKeyReq;
wh_Packet_she_export_ram_key_res     sheExportRamKeyRes;
wh_Packet_she_init_rng_res           sheInitRngRes;
wh_Packet_she_rnd_res                sheRndRes;
wh_Packet_she_extend_seed_req        sheExtendSeedReq;
wh_Packet_she_extend_seed_res        sheExtendSeedRes;
wh_Packet_she_enc_ecb_req            sheEncEcbReq;
wh_Packet_she_enc_ecb_res            sheEncEcbRes;
wh_Packet_she_enc_cbc_req            sheEncCbcReq;
wh_Packet_she_enc_cbc_res            sheEncCbcRes;
wh_Packet_she_enc_ecb_req            sheDecEcbReq;
wh_Packet_she_enc_ecb_res            sheDecEcbRes;
wh_Packet_she_enc_cbc_req            sheDecCbcReq;
wh_Packet_she_enc_cbc_res            sheDecCbcRes;
wh_Packet_she_gen_mac_req            sheGenMacReq;
wh_Packet_she_gen_mac_res            sheGenMacRes;
wh_Packet_she_verify_mac_req         sheVerifyMacReq;
wh_Packet_she_verify_mac_res         sheVerifyMacRes;
#endif /* WOLFHSM_CFG_SHE_EXTENSION */


#endif /* WH_TEST_CHECK_STRUCT_PADDING_C_ */
