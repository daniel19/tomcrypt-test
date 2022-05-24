LIBPATH=./src/lib/libtomcrypt-1.18.2/libtomcrypt.a
INCPATH=./src/lib/libtomcrypt-1.18.2/src/headers/
INCPATH+=/usr/include/openssl/


OBJECTS=./src/lib/libtomcrypt-1.18.2/src/ciphers/aes/aes.o ./src/lib/libtomcrypt-1.18.2/src/ciphers/aes/aes_enc.o ./src/lib/libtomcrypt-1.18.2/src/ciphers/anubis.o ./src/lib/libtomcrypt-1.18.2/src/ciphers/blowfish.o \
./src/lib/libtomcrypt-1.18.2/src/ciphers/camellia.o ./src/lib/libtomcrypt-1.18.2/src/ciphers/cast5.o ./src/lib/libtomcrypt-1.18.2/src/ciphers/des.o ./src/lib/libtomcrypt-1.18.2/src/ciphers/kasumi.o ./src/lib/libtomcrypt-1.18.2/src/ciphers/khazad.o \
./src/lib/libtomcrypt-1.18.2/src/ciphers/kseed.o ./src/lib/libtomcrypt-1.18.2/src/ciphers/multi2.o ./src/lib/libtomcrypt-1.18.2/src/ciphers/noekeon.o ./src/lib/libtomcrypt-1.18.2/src/ciphers/rc2.o ./src/lib/libtomcrypt-1.18.2/src/ciphers/rc5.o \
./src/lib/libtomcrypt-1.18.2/src/ciphers/rc6.o ./src/lib/libtomcrypt-1.18.2/src/ciphers/safer/safer.o ./src/lib/libtomcrypt-1.18.2/src/ciphers/safer/saferp.o ./src/lib/libtomcrypt-1.18.2/src/ciphers/skipjack.o \
./src/lib/libtomcrypt-1.18.2/src/ciphers/twofish/twofish.o ./src/lib/libtomcrypt-1.18.2/src/ciphers/xtea.o ./src/lib/libtomcrypt-1.18.2/src/encauth/ccm/ccm_add_aad.o \
./src/lib/libtomcrypt-1.18.2/src/encauth/ccm/ccm_add_nonce.o ./src/lib/libtomcrypt-1.18.2/src/encauth/ccm/ccm_done.o ./src/lib/libtomcrypt-1.18.2/src/encauth/ccm/ccm_init.o \
./src/lib/libtomcrypt-1.18.2/src/encauth/ccm/ccm_memory.o ./src/lib/libtomcrypt-1.18.2/src/encauth/ccm/ccm_process.o ./src/lib/libtomcrypt-1.18.2/src/encauth/ccm/ccm_reset.o \
./src/lib/libtomcrypt-1.18.2/src/encauth/ccm/ccm_test.o ./src/lib/libtomcrypt-1.18.2/src/encauth/chachapoly/chacha20poly1305_add_aad.o \
./src/lib/libtomcrypt-1.18.2/src/encauth/chachapoly/chacha20poly1305_decrypt.o ./src/lib/libtomcrypt-1.18.2/src/encauth/chachapoly/chacha20poly1305_done.o \
./src/lib/libtomcrypt-1.18.2/src/encauth/chachapoly/chacha20poly1305_encrypt.o ./src/lib/libtomcrypt-1.18.2/src/encauth/chachapoly/chacha20poly1305_init.o \
./src/lib/libtomcrypt-1.18.2/src/encauth/chachapoly/chacha20poly1305_memory.o ./src/lib/libtomcrypt-1.18.2/src/encauth/chachapoly/chacha20poly1305_setiv.o \
./src/lib/libtomcrypt-1.18.2/src/encauth/chachapoly/chacha20poly1305_setiv_rfc7905.o \
./src/lib/libtomcrypt-1.18.2/src/encauth/chachapoly/chacha20poly1305_test.o ./src/lib/libtomcrypt-1.18.2/src/encauth/eax/eax_addheader.o \
./src/lib/libtomcrypt-1.18.2/src/encauth/eax/eax_decrypt.o ./src/lib/libtomcrypt-1.18.2/src/encauth/eax/eax_decrypt_verify_memory.o ./src/lib/libtomcrypt-1.18.2/src/encauth/eax/eax_done.o \
./src/lib/libtomcrypt-1.18.2/src/encauth/eax/eax_encrypt.o ./src/lib/libtomcrypt-1.18.2/src/encauth/eax/eax_encrypt_authenticate_memory.o \
./src/lib/libtomcrypt-1.18.2/src/encauth/eax/eax_init.o ./src/lib/libtomcrypt-1.18.2/src/encauth/eax/eax_test.o ./src/lib/libtomcrypt-1.18.2/src/encauth/gcm/gcm_add_aad.o \
./src/lib/libtomcrypt-1.18.2/src/encauth/gcm/gcm_add_iv.o ./src/lib/libtomcrypt-1.18.2/src/encauth/gcm/gcm_done.o ./src/lib/libtomcrypt-1.18.2/src/encauth/gcm/gcm_gf_mult.o \
./src/lib/libtomcrypt-1.18.2/src/encauth/gcm/gcm_init.o ./src/lib/libtomcrypt-1.18.2/src/encauth/gcm/gcm_memory.o ./src/lib/libtomcrypt-1.18.2/src/encauth/gcm/gcm_mult_h.o \
./src/lib/libtomcrypt-1.18.2/src/encauth/gcm/gcm_process.o ./src/lib/libtomcrypt-1.18.2/src/encauth/gcm/gcm_reset.o ./src/lib/libtomcrypt-1.18.2/src/encauth/gcm/gcm_test.o \
./src/lib/libtomcrypt-1.18.2/src/encauth/ocb/ocb_decrypt.o ./src/lib/libtomcrypt-1.18.2/src/encauth/ocb/ocb_decrypt_verify_memory.o \
./src/lib/libtomcrypt-1.18.2/src/encauth/ocb/ocb_done_decrypt.o ./src/lib/libtomcrypt-1.18.2/src/encauth/ocb/ocb_done_encrypt.o ./src/lib/libtomcrypt-1.18.2/src/encauth/ocb/ocb_encrypt.o \
./src/lib/libtomcrypt-1.18.2/src/encauth/ocb/ocb_encrypt_authenticate_memory.o ./src/lib/libtomcrypt-1.18.2/src/encauth/ocb/ocb_init.o ./src/lib/libtomcrypt-1.18.2/src/encauth/ocb/ocb_ntz.o \
./src/lib/libtomcrypt-1.18.2/src/encauth/ocb/ocb_shift_xor.o ./src/lib/libtomcrypt-1.18.2/src/encauth/ocb/ocb_test.o ./src/lib/libtomcrypt-1.18.2/src/encauth/ocb/s_ocb_done.o \
./src/lib/libtomcrypt-1.18.2/src/encauth/ocb3/ocb3_add_aad.o ./src/lib/libtomcrypt-1.18.2/src/encauth/ocb3/ocb3_decrypt.o ./src/lib/libtomcrypt-1.18.2/src/encauth/ocb3/ocb3_decrypt_last.o \
./src/lib/libtomcrypt-1.18.2/src/encauth/ocb3/ocb3_decrypt_verify_memory.o ./src/lib/libtomcrypt-1.18.2/src/encauth/ocb3/ocb3_done.o \
./src/lib/libtomcrypt-1.18.2/src/encauth/ocb3/ocb3_encrypt.o ./src/lib/libtomcrypt-1.18.2/src/encauth/ocb3/ocb3_encrypt_authenticate_memory.o \
./src/lib/libtomcrypt-1.18.2/src/encauth/ocb3/ocb3_encrypt_last.o ./src/lib/libtomcrypt-1.18.2/src/encauth/ocb3/ocb3_init.o ./src/lib/libtomcrypt-1.18.2/src/encauth/ocb3/ocb3_int_ntz.o \
./src/lib/libtomcrypt-1.18.2/src/encauth/ocb3/ocb3_int_xor_blocks.o ./src/lib/libtomcrypt-1.18.2/src/encauth/ocb3/ocb3_test.o ./src/lib/libtomcrypt-1.18.2/src/hashes/blake2b.o \
./src/lib/libtomcrypt-1.18.2/src/hashes/blake2s.o ./src/lib/libtomcrypt-1.18.2/src/hashes/chc/chc.o ./src/lib/libtomcrypt-1.18.2/src/hashes/helper/hash_file.o \
./src/lib/libtomcrypt-1.18.2/src/hashes/helper/hash_filehandle.o ./src/lib/libtomcrypt-1.18.2/src/hashes/helper/hash_memory.o \
./src/lib/libtomcrypt-1.18.2/src/hashes/helper/hash_memory_multi.o ./src/lib/libtomcrypt-1.18.2/src/hashes/md2.o ./src/lib/libtomcrypt-1.18.2/src/hashes/md4.o ./src/lib/libtomcrypt-1.18.2/src/hashes/md5.o \
./src/lib/libtomcrypt-1.18.2/src/hashes/rmd128.o ./src/lib/libtomcrypt-1.18.2/src/hashes/rmd160.o ./src/lib/libtomcrypt-1.18.2/src/hashes/rmd256.o ./src/lib/libtomcrypt-1.18.2/src/hashes/rmd320.o ./src/lib/libtomcrypt-1.18.2/src/hashes/sha1.o \
./src/lib/libtomcrypt-1.18.2/src/hashes/sha2/sha224.o ./src/lib/libtomcrypt-1.18.2/src/hashes/sha2/sha256.o ./src/lib/libtomcrypt-1.18.2/src/hashes/sha2/sha384.o ./src/lib/libtomcrypt-1.18.2/src/hashes/sha2/sha512.o \
./src/lib/libtomcrypt-1.18.2/src/hashes/sha2/sha512_224.o ./src/lib/libtomcrypt-1.18.2/src/hashes/sha2/sha512_256.o ./src/lib/libtomcrypt-1.18.2/src/hashes/sha3.o ./src/lib/libtomcrypt-1.18.2/src/hashes/sha3_test.o \
./src/lib/libtomcrypt-1.18.2/src/hashes/tiger.o ./src/lib/libtomcrypt-1.18.2/src/hashes/whirl/whirl.o ./src/lib/libtomcrypt-1.18.2/src/mac/blake2/blake2bmac.o \
./src/lib/libtomcrypt-1.18.2/src/mac/blake2/blake2bmac_file.o ./src/lib/libtomcrypt-1.18.2/src/mac/blake2/blake2bmac_memory.o \
./src/lib/libtomcrypt-1.18.2/src/mac/blake2/blake2bmac_memory_multi.o ./src/lib/libtomcrypt-1.18.2/src/mac/blake2/blake2bmac_test.o ./src/lib/libtomcrypt-1.18.2/src/mac/blake2/blake2smac.o \
./src/lib/libtomcrypt-1.18.2/src/mac/blake2/blake2smac_file.o ./src/lib/libtomcrypt-1.18.2/src/mac/blake2/blake2smac_memory.o \
./src/lib/libtomcrypt-1.18.2/src/mac/blake2/blake2smac_memory_multi.o ./src/lib/libtomcrypt-1.18.2/src/mac/blake2/blake2smac_test.o ./src/lib/libtomcrypt-1.18.2/src/mac/f9/f9_done.o \
./src/lib/libtomcrypt-1.18.2/src/mac/f9/f9_file.o ./src/lib/libtomcrypt-1.18.2/src/mac/f9/f9_init.o ./src/lib/libtomcrypt-1.18.2/src/mac/f9/f9_memory.o ./src/lib/libtomcrypt-1.18.2/src/mac/f9/f9_memory_multi.o \
./src/lib/libtomcrypt-1.18.2/src/mac/f9/f9_process.o ./src/lib/libtomcrypt-1.18.2/src/mac/f9/f9_test.o ./src/lib/libtomcrypt-1.18.2/src/mac/hmac/hmac_done.o ./src/lib/libtomcrypt-1.18.2/src/mac/hmac/hmac_file.o \
./src/lib/libtomcrypt-1.18.2/src/mac/hmac/hmac_init.o ./src/lib/libtomcrypt-1.18.2/src/mac/hmac/hmac_memory.o ./src/lib/libtomcrypt-1.18.2/src/mac/hmac/hmac_memory_multi.o \
./src/lib/libtomcrypt-1.18.2/src/mac/hmac/hmac_process.o ./src/lib/libtomcrypt-1.18.2/src/mac/hmac/hmac_test.o ./src/lib/libtomcrypt-1.18.2/src/mac/omac/omac_done.o ./src/lib/libtomcrypt-1.18.2/src/mac/omac/omac_file.o \
./src/lib/libtomcrypt-1.18.2/src/mac/omac/omac_init.o ./src/lib/libtomcrypt-1.18.2/src/mac/omac/omac_memory.o ./src/lib/libtomcrypt-1.18.2/src/mac/omac/omac_memory_multi.o \
./src/lib/libtomcrypt-1.18.2/src/mac/omac/omac_process.o ./src/lib/libtomcrypt-1.18.2/src/mac/omac/omac_test.o ./src/lib/libtomcrypt-1.18.2/src/mac/pelican/pelican.o \
./src/lib/libtomcrypt-1.18.2/src/mac/pelican/pelican_memory.o ./src/lib/libtomcrypt-1.18.2/src/mac/pelican/pelican_test.o ./src/lib/libtomcrypt-1.18.2/src/mac/pmac/pmac_done.o \
./src/lib/libtomcrypt-1.18.2/src/mac/pmac/pmac_file.o ./src/lib/libtomcrypt-1.18.2/src/mac/pmac/pmac_init.o ./src/lib/libtomcrypt-1.18.2/src/mac/pmac/pmac_memory.o \
./src/lib/libtomcrypt-1.18.2/src/mac/pmac/pmac_memory_multi.o ./src/lib/libtomcrypt-1.18.2/src/mac/pmac/pmac_ntz.o ./src/lib/libtomcrypt-1.18.2/src/mac/pmac/pmac_process.o \
./src/lib/libtomcrypt-1.18.2/src/mac/pmac/pmac_shift_xor.o ./src/lib/libtomcrypt-1.18.2/src/mac/pmac/pmac_test.o ./src/lib/libtomcrypt-1.18.2/src/mac/poly1305/poly1305.o \
./src/lib/libtomcrypt-1.18.2/src/mac/poly1305/poly1305_file.o ./src/lib/libtomcrypt-1.18.2/src/mac/poly1305/poly1305_memory.o \
./src/lib/libtomcrypt-1.18.2/src/mac/poly1305/poly1305_memory_multi.o ./src/lib/libtomcrypt-1.18.2/src/mac/poly1305/poly1305_test.o ./src/lib/libtomcrypt-1.18.2/src/mac/xcbc/xcbc_done.o \
./src/lib/libtomcrypt-1.18.2/src/mac/xcbc/xcbc_file.o ./src/lib/libtomcrypt-1.18.2/src/mac/xcbc/xcbc_init.o ./src/lib/libtomcrypt-1.18.2/src/mac/xcbc/xcbc_memory.o \
./src/lib/libtomcrypt-1.18.2/src/mac/xcbc/xcbc_memory_multi.o ./src/lib/libtomcrypt-1.18.2/src/mac/xcbc/xcbc_process.o ./src/lib/libtomcrypt-1.18.2/src/mac/xcbc/xcbc_test.o \
./src/lib/libtomcrypt-1.18.2/src/math/fp/ltc_ecc_fp_mulmod.o ./src/lib/libtomcrypt-1.18.2/src/math/gmp_desc.o ./src/lib/libtomcrypt-1.18.2/src/math/ltm_desc.o ./src/lib/libtomcrypt-1.18.2/src/math/multi.o \
./src/lib/libtomcrypt-1.18.2/src/math/radix_to_bin.o ./src/lib/libtomcrypt-1.18.2/src/math/rand_bn.o ./src/lib/libtomcrypt-1.18.2/src/math/rand_prime.o ./src/lib/libtomcrypt-1.18.2/src/math/tfm_desc.o ./src/lib/libtomcrypt-1.18.2/src/misc/adler32.o \
./src/lib/libtomcrypt-1.18.2/src/misc/base64/base64_decode.o ./src/lib/libtomcrypt-1.18.2/src/misc/base64/base64_encode.o ./src/lib/libtomcrypt-1.18.2/src/misc/burn_stack.o \
./src/lib/libtomcrypt-1.18.2/src/misc/compare_testvector.o ./src/lib/libtomcrypt-1.18.2/src/misc/crc32.o ./src/lib/libtomcrypt-1.18.2/src/misc/crypt/crypt.o ./src/lib/libtomcrypt-1.18.2/src/misc/crypt/crypt_argchk.o \
./src/lib/libtomcrypt-1.18.2/src/misc/crypt/crypt_cipher_descriptor.o ./src/lib/libtomcrypt-1.18.2/src/misc/crypt/crypt_cipher_is_valid.o \
./src/lib/libtomcrypt-1.18.2/src/misc/crypt/crypt_constants.o ./src/lib/libtomcrypt-1.18.2/src/misc/crypt/crypt_find_cipher.o \
./src/lib/libtomcrypt-1.18.2/src/misc/crypt/crypt_find_cipher_any.o ./src/lib/libtomcrypt-1.18.2/src/misc/crypt/crypt_find_cipher_id.o \
./src/lib/libtomcrypt-1.18.2/src/misc/crypt/crypt_find_hash.o ./src/lib/libtomcrypt-1.18.2/src/misc/crypt/crypt_find_hash_any.o \
./src/lib/libtomcrypt-1.18.2/src/misc/crypt/crypt_find_hash_id.o ./src/lib/libtomcrypt-1.18.2/src/misc/crypt/crypt_find_hash_oid.o \
./src/lib/libtomcrypt-1.18.2/src/misc/crypt/crypt_find_prng.o ./src/lib/libtomcrypt-1.18.2/src/misc/crypt/crypt_fsa.o ./src/lib/libtomcrypt-1.18.2/src/misc/crypt/crypt_hash_descriptor.o \
./src/lib/libtomcrypt-1.18.2/src/misc/crypt/crypt_hash_is_valid.o ./src/lib/libtomcrypt-1.18.2/src/misc/crypt/crypt_inits.o \
./src/lib/libtomcrypt-1.18.2/src/misc/crypt/crypt_ltc_mp_descriptor.o ./src/lib/libtomcrypt-1.18.2/src/misc/crypt/crypt_prng_descriptor.o \
./src/lib/libtomcrypt-1.18.2/src/misc/crypt/crypt_prng_is_valid.o ./src/lib/libtomcrypt-1.18.2/src/misc/crypt/crypt_prng_rng_descriptor.o \
./src/lib/libtomcrypt-1.18.2/src/misc/crypt/crypt_register_all_ciphers.o ./src/lib/libtomcrypt-1.18.2/src/misc/crypt/crypt_register_all_hashes.o \
./src/lib/libtomcrypt-1.18.2/src/misc/crypt/crypt_register_all_prngs.o ./src/lib/libtomcrypt-1.18.2/src/misc/crypt/crypt_register_cipher.o \
./src/lib/libtomcrypt-1.18.2/src/misc/crypt/crypt_register_hash.o ./src/lib/libtomcrypt-1.18.2/src/misc/crypt/crypt_register_prng.o ./src/lib/libtomcrypt-1.18.2/src/misc/crypt/crypt_sizes.o \
./src/lib/libtomcrypt-1.18.2/src/misc/crypt/crypt_unregister_cipher.o ./src/lib/libtomcrypt-1.18.2/src/misc/crypt/crypt_unregister_hash.o \
./src/lib/libtomcrypt-1.18.2/src/misc/crypt/crypt_unregister_prng.o ./src/lib/libtomcrypt-1.18.2/src/misc/error_to_string.o ./src/lib/libtomcrypt-1.18.2/src/misc/hkdf/hkdf.o \
./src/lib/libtomcrypt-1.18.2/src/misc/hkdf/hkdf_test.o ./src/lib/libtomcrypt-1.18.2/src/misc/mem_neq.o ./src/lib/libtomcrypt-1.18.2/src/misc/pk_get_oid.o ./src/lib/libtomcrypt-1.18.2/src/misc/pkcs5/pkcs_5_1.o \
./src/lib/libtomcrypt-1.18.2/src/misc/pkcs5/pkcs_5_2.o ./src/lib/libtomcrypt-1.18.2/src/misc/pkcs5/pkcs_5_test.o ./src/lib/libtomcrypt-1.18.2/src/misc/zeromem.o ./src/lib/libtomcrypt-1.18.2/src/modes/cbc/cbc_decrypt.o \
./src/lib/libtomcrypt-1.18.2/src/modes/cbc/cbc_done.o ./src/lib/libtomcrypt-1.18.2/src/modes/cbc/cbc_encrypt.o ./src/lib/libtomcrypt-1.18.2/src/modes/cbc/cbc_getiv.o \
./src/lib/libtomcrypt-1.18.2/src/modes/cbc/cbc_setiv.o ./src/lib/libtomcrypt-1.18.2/src/modes/cbc/cbc_start.o ./src/lib/libtomcrypt-1.18.2/src/modes/cfb/cfb_decrypt.o \
./src/lib/libtomcrypt-1.18.2/src/modes/cfb/cfb_done.o ./src/lib/libtomcrypt-1.18.2/src/modes/cfb/cfb_encrypt.o ./src/lib/libtomcrypt-1.18.2/src/modes/cfb/cfb_getiv.o \
./src/lib/libtomcrypt-1.18.2/src/modes/cfb/cfb_setiv.o ./src/lib/libtomcrypt-1.18.2/src/modes/cfb/cfb_start.o ./src/lib/libtomcrypt-1.18.2/src/modes/ctr/ctr_decrypt.o \
./src/lib/libtomcrypt-1.18.2/src/modes/ctr/ctr_done.o ./src/lib/libtomcrypt-1.18.2/src/modes/ctr/ctr_encrypt.o ./src/lib/libtomcrypt-1.18.2/src/modes/ctr/ctr_getiv.o \
./src/lib/libtomcrypt-1.18.2/src/modes/ctr/ctr_setiv.o ./src/lib/libtomcrypt-1.18.2/src/modes/ctr/ctr_start.o ./src/lib/libtomcrypt-1.18.2/src/modes/ctr/ctr_test.o \
./src/lib/libtomcrypt-1.18.2/src/modes/ecb/ecb_decrypt.o ./src/lib/libtomcrypt-1.18.2/src/modes/ecb/ecb_done.o ./src/lib/libtomcrypt-1.18.2/src/modes/ecb/ecb_encrypt.o \
./src/lib/libtomcrypt-1.18.2/src/modes/ecb/ecb_start.o ./src/lib/libtomcrypt-1.18.2/src/modes/f8/f8_decrypt.o ./src/lib/libtomcrypt-1.18.2/src/modes/f8/f8_done.o ./src/lib/libtomcrypt-1.18.2/src/modes/f8/f8_encrypt.o \
./src/lib/libtomcrypt-1.18.2/src/modes/f8/f8_getiv.o ./src/lib/libtomcrypt-1.18.2/src/modes/f8/f8_setiv.o ./src/lib/libtomcrypt-1.18.2/src/modes/f8/f8_start.o ./src/lib/libtomcrypt-1.18.2/src/modes/f8/f8_test_mode.o \
./src/lib/libtomcrypt-1.18.2/src/modes/lrw/lrw_decrypt.o ./src/lib/libtomcrypt-1.18.2/src/modes/lrw/lrw_done.o ./src/lib/libtomcrypt-1.18.2/src/modes/lrw/lrw_encrypt.o \
./src/lib/libtomcrypt-1.18.2/src/modes/lrw/lrw_getiv.o ./src/lib/libtomcrypt-1.18.2/src/modes/lrw/lrw_process.o ./src/lib/libtomcrypt-1.18.2/src/modes/lrw/lrw_setiv.o \
./src/lib/libtomcrypt-1.18.2/src/modes/lrw/lrw_start.o ./src/lib/libtomcrypt-1.18.2/src/modes/lrw/lrw_test.o ./src/lib/libtomcrypt-1.18.2/src/modes/ofb/ofb_decrypt.o ./src/lib/libtomcrypt-1.18.2/src/modes/ofb/ofb_done.o \
./src/lib/libtomcrypt-1.18.2/src/modes/ofb/ofb_encrypt.o ./src/lib/libtomcrypt-1.18.2/src/modes/ofb/ofb_getiv.o ./src/lib/libtomcrypt-1.18.2/src/modes/ofb/ofb_setiv.o \
./src/lib/libtomcrypt-1.18.2/src/modes/ofb/ofb_start.o ./src/lib/libtomcrypt-1.18.2/src/modes/xts/xts_decrypt.o ./src/lib/libtomcrypt-1.18.2/src/modes/xts/xts_done.o \
./src/lib/libtomcrypt-1.18.2/src/modes/xts/xts_encrypt.o ./src/lib/libtomcrypt-1.18.2/src/modes/xts/xts_init.o ./src/lib/libtomcrypt-1.18.2/src/modes/xts/xts_mult_x.o \
./src/lib/libtomcrypt-1.18.2/src/modes/xts/xts_test.o ./src/lib/libtomcrypt-1.18.2/src/pk/asn1/der/bit/der_decode_bit_string.o \
./src/lib/libtomcrypt-1.18.2/src/pk/asn1/der/bit/der_decode_raw_bit_string.o ./src/lib/libtomcrypt-1.18.2/src/pk/asn1/der/bit/der_encode_bit_string.o \
./src/lib/libtomcrypt-1.18.2/src/pk/asn1/der/bit/der_encode_raw_bit_string.o ./src/lib/libtomcrypt-1.18.2/src/pk/asn1/der/bit/der_length_bit_string.o \
./src/lib/libtomcrypt-1.18.2/src/pk/asn1/der/boolean/der_decode_boolean.o ./src/lib/libtomcrypt-1.18.2/src/pk/asn1/der/boolean/der_encode_boolean.o \
./src/lib/libtomcrypt-1.18.2/src/pk/asn1/der/boolean/der_length_boolean.o ./src/lib/libtomcrypt-1.18.2/src/pk/asn1/der/choice/der_decode_choice.o \
./src/lib/libtomcrypt-1.18.2/src/pk/asn1/der/generalizedtime/der_decode_generalizedtime.o \
./src/lib/libtomcrypt-1.18.2/src/pk/asn1/der/generalizedtime/der_encode_generalizedtime.o \
./src/lib/libtomcrypt-1.18.2/src/pk/asn1/der/generalizedtime/der_length_generalizedtime.o \
./src/lib/libtomcrypt-1.18.2/src/pk/asn1/der/ia5/der_decode_ia5_string.o ./src/lib/libtomcrypt-1.18.2/src/pk/asn1/der/ia5/der_encode_ia5_string.o \
./src/lib/libtomcrypt-1.18.2/src/pk/asn1/der/ia5/der_length_ia5_string.o ./src/lib/libtomcrypt-1.18.2/src/pk/asn1/der/integer/der_decode_integer.o \
./src/lib/libtomcrypt-1.18.2/src/pk/asn1/der/integer/der_encode_integer.o ./src/lib/libtomcrypt-1.18.2/src/pk/asn1/der/integer/der_length_integer.o \
./src/lib/libtomcrypt-1.18.2/src/pk/asn1/der/object_identifier/der_decode_object_identifier.o \
./src/lib/libtomcrypt-1.18.2/src/pk/asn1/der/object_identifier/der_encode_object_identifier.o \
./src/lib/libtomcrypt-1.18.2/src/pk/asn1/der/object_identifier/der_length_object_identifier.o \
./src/lib/libtomcrypt-1.18.2/src/pk/asn1/der/octet/der_decode_octet_string.o ./src/lib/libtomcrypt-1.18.2/src/pk/asn1/der/octet/der_encode_octet_string.o \
./src/lib/libtomcrypt-1.18.2/src/pk/asn1/der/octet/der_length_octet_string.o \
./src/lib/libtomcrypt-1.18.2/src/pk/asn1/der/printable_string/der_decode_printable_string.o \
./src/lib/libtomcrypt-1.18.2/src/pk/asn1/der/printable_string/der_encode_printable_string.o \
./src/lib/libtomcrypt-1.18.2/src/pk/asn1/der/printable_string/der_length_printable_string.o \
./src/lib/libtomcrypt-1.18.2/src/pk/asn1/der/sequence/der_decode_sequence_ex.o \
./src/lib/libtomcrypt-1.18.2/src/pk/asn1/der/sequence/der_decode_sequence_flexi.o \
./src/lib/libtomcrypt-1.18.2/src/pk/asn1/der/sequence/der_decode_sequence_multi.o \
./src/lib/libtomcrypt-1.18.2/src/pk/asn1/der/sequence/der_decode_subject_public_key_info.o \
./src/lib/libtomcrypt-1.18.2/src/pk/asn1/der/sequence/der_encode_sequence_ex.o \
./src/lib/libtomcrypt-1.18.2/src/pk/asn1/der/sequence/der_encode_sequence_multi.o \
./src/lib/libtomcrypt-1.18.2/src/pk/asn1/der/sequence/der_encode_subject_public_key_info.o \
./src/lib/libtomcrypt-1.18.2/src/pk/asn1/der/sequence/der_length_sequence.o ./src/lib/libtomcrypt-1.18.2/src/pk/asn1/der/sequence/der_sequence_free.o \
./src/lib/libtomcrypt-1.18.2/src/pk/asn1/der/sequence/der_sequence_shrink.o ./src/lib/libtomcrypt-1.18.2/src/pk/asn1/der/set/der_encode_set.o \
./src/lib/libtomcrypt-1.18.2/src/pk/asn1/der/set/der_encode_setof.o ./src/lib/libtomcrypt-1.18.2/src/pk/asn1/der/short_integer/der_decode_short_integer.o \
./src/lib/libtomcrypt-1.18.2/src/pk/asn1/der/short_integer/der_encode_short_integer.o \
./src/lib/libtomcrypt-1.18.2/src/pk/asn1/der/short_integer/der_length_short_integer.o \
./src/lib/libtomcrypt-1.18.2/src/pk/asn1/der/teletex_string/der_decode_teletex_string.o \
./src/lib/libtomcrypt-1.18.2/src/pk/asn1/der/teletex_string/der_length_teletex_string.o \
./src/lib/libtomcrypt-1.18.2/src/pk/asn1/der/utctime/der_decode_utctime.o ./src/lib/libtomcrypt-1.18.2/src/pk/asn1/der/utctime/der_encode_utctime.o \
./src/lib/libtomcrypt-1.18.2/src/pk/asn1/der/utctime/der_length_utctime.o ./src/lib/libtomcrypt-1.18.2/src/pk/asn1/der/utf8/der_decode_utf8_string.o \
./src/lib/libtomcrypt-1.18.2/src/pk/asn1/der/utf8/der_encode_utf8_string.o ./src/lib/libtomcrypt-1.18.2/src/pk/asn1/der/utf8/der_length_utf8_string.o \
./src/lib/libtomcrypt-1.18.2/src/pk/dh/dh.o ./src/lib/libtomcrypt-1.18.2/src/pk/dh/dh_check_pubkey.o ./src/lib/libtomcrypt-1.18.2/src/pk/dh/dh_export.o ./src/lib/libtomcrypt-1.18.2/src/pk/dh/dh_export_key.o \
./src/lib/libtomcrypt-1.18.2/src/pk/dh/dh_free.o ./src/lib/libtomcrypt-1.18.2/src/pk/dh/dh_generate_key.o ./src/lib/libtomcrypt-1.18.2/src/pk/dh/dh_import.o ./src/lib/libtomcrypt-1.18.2/src/pk/dh/dh_set.o \
./src/lib/libtomcrypt-1.18.2/src/pk/dh/dh_set_pg_dhparam.o ./src/lib/libtomcrypt-1.18.2/src/pk/dh/dh_shared_secret.o ./src/lib/libtomcrypt-1.18.2/src/pk/dsa/dsa_decrypt_key.o \
./src/lib/libtomcrypt-1.18.2/src/pk/dsa/dsa_encrypt_key.o ./src/lib/libtomcrypt-1.18.2/src/pk/dsa/dsa_export.o ./src/lib/libtomcrypt-1.18.2/src/pk/dsa/dsa_free.o \
./src/lib/libtomcrypt-1.18.2/src/pk/dsa/dsa_generate_key.o ./src/lib/libtomcrypt-1.18.2/src/pk/dsa/dsa_generate_pqg.o ./src/lib/libtomcrypt-1.18.2/src/pk/dsa/dsa_import.o \
./src/lib/libtomcrypt-1.18.2/src/pk/dsa/dsa_make_key.o ./src/lib/libtomcrypt-1.18.2/src/pk/dsa/dsa_set.o ./src/lib/libtomcrypt-1.18.2/src/pk/dsa/dsa_set_pqg_dsaparam.o \
./src/lib/libtomcrypt-1.18.2/src/pk/dsa/dsa_shared_secret.o ./src/lib/libtomcrypt-1.18.2/src/pk/dsa/dsa_sign_hash.o ./src/lib/libtomcrypt-1.18.2/src/pk/dsa/dsa_verify_hash.o \
./src/lib/libtomcrypt-1.18.2/src/pk/dsa/dsa_verify_key.o ./src/lib/libtomcrypt-1.18.2/src/pk/ecc/ecc.o ./src/lib/libtomcrypt-1.18.2/src/pk/ecc/ecc_ansi_x963_export.o \
./src/lib/libtomcrypt-1.18.2/src/pk/ecc/ecc_ansi_x963_import.o ./src/lib/libtomcrypt-1.18.2/src/pk/ecc/ecc_decrypt_key.o ./src/lib/libtomcrypt-1.18.2/src/pk/ecc/ecc_encrypt_key.o \
./src/lib/libtomcrypt-1.18.2/src/pk/ecc/ecc_export.o ./src/lib/libtomcrypt-1.18.2/src/pk/ecc/ecc_free.o ./src/lib/libtomcrypt-1.18.2/src/pk/ecc/ecc_get_size.o ./src/lib/libtomcrypt-1.18.2/src/pk/ecc/ecc_import.o \
./src/lib/libtomcrypt-1.18.2/src/pk/ecc/ecc_make_key.o ./src/lib/libtomcrypt-1.18.2/src/pk/ecc/ecc_shared_secret.o ./src/lib/libtomcrypt-1.18.2/src/pk/ecc/ecc_sign_hash.o \
./src/lib/libtomcrypt-1.18.2/src/pk/ecc/ecc_sizes.o ./src/lib/libtomcrypt-1.18.2/src/pk/ecc/ecc_test.o ./src/lib/libtomcrypt-1.18.2/src/pk/ecc/ecc_verify_hash.o \
./src/lib/libtomcrypt-1.18.2/src/pk/ecc/ltc_ecc_is_valid_idx.o ./src/lib/libtomcrypt-1.18.2/src/pk/ecc/ltc_ecc_map.o ./src/lib/libtomcrypt-1.18.2/src/pk/ecc/ltc_ecc_mul2add.o \
./src/lib/libtomcrypt-1.18.2/src/pk/ecc/ltc_ecc_mulmod.o ./src/lib/libtomcrypt-1.18.2/src/pk/ecc/ltc_ecc_mulmod_timing.o ./src/lib/libtomcrypt-1.18.2/src/pk/ecc/ltc_ecc_points.o \
./src/lib/libtomcrypt-1.18.2/src/pk/ecc/ltc_ecc_projective_add_point.o ./src/lib/libtomcrypt-1.18.2/src/pk/ecc/ltc_ecc_projective_dbl_point.o \
./src/lib/libtomcrypt-1.18.2/src/pk/katja/katja_decrypt_key.o ./src/lib/libtomcrypt-1.18.2/src/pk/katja/katja_encrypt_key.o ./src/lib/libtomcrypt-1.18.2/src/pk/katja/katja_export.o \
./src/lib/libtomcrypt-1.18.2/src/pk/katja/katja_exptmod.o ./src/lib/libtomcrypt-1.18.2/src/pk/katja/katja_free.o ./src/lib/libtomcrypt-1.18.2/src/pk/katja/katja_import.o \
./src/lib/libtomcrypt-1.18.2/src/pk/katja/katja_make_key.o ./src/lib/libtomcrypt-1.18.2/src/pk/pkcs1/pkcs_1_i2osp.o ./src/lib/libtomcrypt-1.18.2/src/pk/pkcs1/pkcs_1_mgf1.o \
./src/lib/libtomcrypt-1.18.2/src/pk/pkcs1/pkcs_1_oaep_decode.o ./src/lib/libtomcrypt-1.18.2/src/pk/pkcs1/pkcs_1_oaep_encode.o ./src/lib/libtomcrypt-1.18.2/src/pk/pkcs1/pkcs_1_os2ip.o \
./src/lib/libtomcrypt-1.18.2/src/pk/pkcs1/pkcs_1_pss_decode.o ./src/lib/libtomcrypt-1.18.2/src/pk/pkcs1/pkcs_1_pss_encode.o ./src/lib/libtomcrypt-1.18.2/src/pk/pkcs1/pkcs_1_v1_5_decode.o \
./src/lib/libtomcrypt-1.18.2/src/pk/pkcs1/pkcs_1_v1_5_encode.o ./src/lib/libtomcrypt-1.18.2/src/pk/rsa/rsa_decrypt_key.o ./src/lib/libtomcrypt-1.18.2/src/pk/rsa/rsa_encrypt_key.o \
./src/lib/libtomcrypt-1.18.2/src/pk/rsa/rsa_export.o ./src/lib/libtomcrypt-1.18.2/src/pk/rsa/rsa_exptmod.o ./src/lib/libtomcrypt-1.18.2/src/pk/rsa/rsa_free.o ./src/lib/libtomcrypt-1.18.2/src/pk/rsa/rsa_get_size.o \
./src/lib/libtomcrypt-1.18.2/src/pk/rsa/rsa_import.o ./src/lib/libtomcrypt-1.18.2/src/pk/rsa/rsa_import_pkcs8.o ./src/lib/libtomcrypt-1.18.2/src/pk/rsa/rsa_import_x509.o \
./src/lib/libtomcrypt-1.18.2/src/pk/rsa/rsa_make_key.o ./src/lib/libtomcrypt-1.18.2/src/pk/rsa/rsa_set.o ./src/lib/libtomcrypt-1.18.2/src/pk/rsa/rsa_sign_hash.o \
./src/lib/libtomcrypt-1.18.2/src/pk/rsa/rsa_sign_saltlen_get.o ./src/lib/libtomcrypt-1.18.2/src/pk/rsa/rsa_verify_hash.o ./src/lib/libtomcrypt-1.18.2/src/prngs/chacha20.o ./src/lib/libtomcrypt-1.18.2/src/prngs/fortuna.o \
./src/lib/libtomcrypt-1.18.2/src/prngs/rc4.o ./src/lib/libtomcrypt-1.18.2/src/prngs/rng_get_bytes.o ./src/lib/libtomcrypt-1.18.2/src/prngs/rng_make_prng.o ./src/lib/libtomcrypt-1.18.2/src/prngs/sober128.o \
./src/lib/libtomcrypt-1.18.2/src/prngs/sprng.o ./src/lib/libtomcrypt-1.18.2/src/prngs/yarrow.o ./src/lib/libtomcrypt-1.18.2/src/stream/chacha/chacha_crypt.o ./src/lib/libtomcrypt-1.18.2/src/stream/chacha/chacha_done.o \
./src/lib/libtomcrypt-1.18.2/src/stream/chacha/chacha_ivctr32.o ./src/lib/libtomcrypt-1.18.2/src/stream/chacha/chacha_ivctr64.o \
./src/lib/libtomcrypt-1.18.2/src/stream/chacha/chacha_keystream.o ./src/lib/libtomcrypt-1.18.2/src/stream/chacha/chacha_setup.o ./src/lib/libtomcrypt-1.18.2/src/stream/chacha/chacha_test.o \
./src/lib/libtomcrypt-1.18.2/src/stream/rc4/rc4_stream.o ./src/lib/libtomcrypt-1.18.2/src/stream/rc4/rc4_test.o ./src/lib/libtomcrypt-1.18.2/src/stream/sober128/sober128_stream.o \
./src/lib/libtomcrypt-1.18.2/src/stream/sober128/sober128_test.o

main: main.o tomcrypt
	gcc -lcrypto -L$(LIBPATH) $(OBJECTS) main.o -o main 

main.o: ./src/main.c
	gcc -Wall -c -I$(INCPATH) ./src/main.c

tomcrypt:
	cd ./src/lib/libtomcrypt-1.18.2/ && make library

all: main

clean:
	rm main.o main $(LIBPATH)
