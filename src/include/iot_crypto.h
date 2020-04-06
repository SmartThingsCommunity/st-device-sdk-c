/* ***************************************************************************
 *
 * Copyright 2019 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#ifndef _IOT_CRYPTO_H_
#define _IOT_CRYPTO_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "sodium.h"

#if __MBED__ == 1
//#include "mbed_config.h"
#if MBED_CONF_STDK_CRYPTO_ED25519 == 1
#define CONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_ED25519
#elif MBED_CONF_STDK_CRYPTO_RSA == 1
#define CONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_RSA
#endif
#endif

#define IOT_ERROR_CRYPTO_BASE64		(IOT_ERROR_CRYPTO_BASE - 1)
#define IOT_ERROR_CRYPTO_BASE64_URLSAFE	(IOT_ERROR_CRYPTO_BASE - 2)
#define IOT_ERROR_CRYPTO_SHA256		(IOT_ERROR_CRYPTO_BASE - 10)
#define IOT_ERROR_CRYPTO_PK_SIGN	(IOT_ERROR_CRYPTO_BASE - 20)
#define IOT_ERROR_CRYPTO_PK_VERIFY	(IOT_ERROR_CRYPTO_BASE - 21)
#define IOT_ERROR_CRYPTO_PK_PARSEKEY	(IOT_ERROR_CRYPTO_BASE - 22)
#define IOT_ERROR_CRYPTO_PK_INVALID_ARG	(IOT_ERROR_CRYPTO_BASE - 23)
#define IOT_ERROR_CRYPTO_PK_INVALID_CTX	(IOT_ERROR_CRYPTO_BASE - 24)
#define IOT_ERROR_CRYPTO_PK_INVALID_KEYLEN (IOT_ERROR_CRYPTO_BASE - 25)
#define IOT_ERROR_CRYPTO_PK_UNKNOWN_KEYTYPE (IOT_ERROR_CRYPTO_BASE - 26)
#define IOT_ERROR_CRYPTO_PK_NULL_FUNC	(IOT_ERROR_CRYPTO_BASE - 27)
#define IOT_ERROR_CRYPTO_PK_ECDH	(IOT_ERROR_CRYPTO_BASE - 28)
#define IOT_ERROR_CRYPTO_ED_KEY_CONVERT	(IOT_ERROR_CRYPTO_BASE - 40)
#define IOT_ERROR_CRYPTO_CIPHER		(IOT_ERROR_CRYPTO_BASE - 60)
#define IOT_ERROR_CRYPTO_CIPHER_UNKNOWN_TYPE (IOT_ERROR_CRYPTO_BASE - 61)
#define IOT_ERROR_CRYPTO_CIPHER_UNKNOWN_MODE (IOT_ERROR_CRYPTO_BASE - 62)
#define IOT_ERROR_CRYPTO_CIPHER_KEYLEN	(IOT_ERROR_CRYPTO_BASE - 63)
#define IOT_ERROR_CRYPTO_CIPHER_IVLEN	(IOT_ERROR_CRYPTO_BASE - 64)
#define IOT_ERROR_CRYPTO_CIPHER_OUTSIZE	(IOT_ERROR_CRYPTO_BASE - 65)
#define IOT_ERROR_CRYPTO_CIPHER_ALIGN	(IOT_ERROR_CRYPTO_BASE - 66)
#define IOT_ERROR_CRYPTO_SS_KDF		(IOT_ERROR_CRYPTO_BASE - 80)

#define IOT_CRYPTO_PK_TYPE_RSA		"RSA"
#define IOT_CRYPTO_PK_TYPE_ED25519	"ED25519"

#define IOT_CRYPTO_ED25519_LEN		crypto_sign_PUBLICKEYBYTES
#define IOT_CRYPTO_SECRET_LEN		32
#define IOT_CRYPTO_IV_LEN		16
#define IOT_CRYPTO_SHA256_LEN		32
#if defined(CONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_ED25519)
#define IOT_CRYPTO_SIGNATURE_LEN	64
#elif defined(CONFIG_STDK_IOT_CORE_CRYPTO_SUPPORT_RSA)
#define IOT_CRYPTO_SIGNATURE_LEN	256
#endif

#define IOT_CRYPTO_CAL_B64_LEN(x)	((((x) + 2) / 3) * 4 + 1)
#define IOT_CRYPTO_CAL_B64_DEC_LEN(x)	(IOT_CRYPTO_ALIGN_B64_LEN(x) / 4 * 3 + 1)
#define IOT_CRYPTO_ALIGN_B64_LEN(x)	((x + 3) & ~3)

/**
 * @brief	Encode a string as a base64 string
 * @param[in]	src	a pointer to a buffer to encode
 * @param[in]	src_len	the size of buffer pointed by src in bytes
 * @param[out]	dst	a pointer to a buffer to store base64 string
 * @param[in]	dst_len	the size of buffer pointed by dst in bytes
 * @param[out]	out_len	the bytes written to dst
 * @retval	IOT_ERROR_NONE	the string is sucessfully encoded
 * @retval	IOT_ERROR_CRYPTO_BASE64	failed to encode the string
 */
iot_error_t iot_crypto_base64_encode(const unsigned char *src, size_t src_len,
                                     unsigned char *dst, size_t dst_len,
                                     size_t *out_len);

/**
 * @brief	Decode a base64 string as a string
 * @param[in]	src	a pointer to a buffer to decode
 * @param[in]	src_len	the size of buffer pointed by src in bytes
 * @param[out]	dst	a pointer to a buffer to store base64 string
 * @param[in]	dst_len	the size of buffer pointed by dst in bytes
 * @param[out]	out_len	the bytes written to dst
 * @retval	IOT_ERROR_NONE	the string is sucessfully decoded
 * @retval	IOT_ERROR_CRYPTO_BASE64	failed to decode the string
 */
iot_error_t iot_crypto_base64_decode(const unsigned char *src, size_t src_len,
                                     unsigned char *dst, size_t dst_len,
                                     size_t *out_len);

/**
 * @brief	Encode a string as a urlsafe base64 string
 * @details	This function replaces url unsafe characters ('+', '/') to
 *		url safe character ('-', '_')
 * @param[in]	src	a pointer to a buffer to encode
 * @param[in]	src_len	the size of buffer pointed by src in bytes
 * @param[out]	dst	a pointer to a buffer to store base64 string
 * @param[in]	dst_len	the size of buffer pointed by dst in bytes
 * @param[out]	out_len	the bytes written to dst
 * @retval	IOT_ERROR_NONE	the string is sucessfully encoded
 * @retval	IOT_ERROR_CRYPTO_BASE64	failed to encode the string in 3rd lib
 * @retval	IOT_ERROR_CRYPTO_BASE64_URLSAFE	failed to encode the string as
 *		urlsafe
 */
iot_error_t iot_crypto_base64_encode_urlsafe(const unsigned char *src, size_t src_len,
                                             unsigned char *dst, size_t dst_len,
                                             size_t *out_len);

/**
 * @brief	Decode a urlsafe base64 string as a string
 * @param[in]	src	a pointer to a buffer to decode
 * @param[in]	src_len	the size of buffer pointed by src in bytes
 * @param[out]	dst	a pointer to a buffer to store base64 string
 * @param[in]	dst_len	the size of buffer pointed by dst in bytes
 * @param[out]	out_len	the bytes written to dst
 * @retval	IOT_ERROR_NONE	the string is sucessfully decoded
 * @retval	IOT_ERROR_CRYPTO_BASE64	failed to decode the string
 * @retval	IOT_ERROR_CRYPTO_BASE64_URLSAFE	failed to encode the string as
 *		urlsafe
 */
iot_error_t iot_crypto_base64_decode_urlsafe(const unsigned char *src, size_t src_len,
                                             unsigned char *dst, size_t dst_len,
                                             size_t *out_len);

/**
 * @brief	Generate a digest by sha256 hash
 * @param[in]	src	a pointer to a buffer to generate a digest
 * @param[in]	src_len	the size of buffer pointed by src in bytes
 * @param[out]	dst	a pointer to a buffer to store a digest
 * @retval	IOT_ERROR_NONE	a digest is sucessfully generated
 * @retval	IOT_ERROR_CRYPTO_SHA256	failed to generate a digest
 */
iot_error_t iot_crypto_sha256(unsigned char *src, size_t src_len, unsigned char *dst);

/*
 * Public Key based operations
 */

typedef struct iot_crypto_pk_context iot_crypto_pk_context_t;

/**
 * @brief Types of registered public key
 */
typedef enum {
	IOT_CRYPTO_PK_RSA,
	IOT_CRYPTO_PK_ED25519,
	IOT_CRYPTO_PK_UNKNOWN,
} iot_crypto_pk_type_t;

/**
 * @brief Contains information of key pair
 */
typedef struct iot_crypto_pk_info {
	iot_crypto_pk_type_t type;	/** @brief type of key pair */
	unsigned char *pubkey;		/** @brief public key of key pair */
	unsigned char *seckey;		/** @brief private key of key pair  */
	size_t pubkey_len;		/** @brief length of public key */
	size_t seckey_len;		/** @brief length of private key */
} iot_crypto_pk_info_t;

/**
 * @brief Contains public key based function lists.
 */
typedef struct iot_crypto_pk_funcs {
	const char *name;		/** @brief string name to know this */
	/**
	 * @brief a pointer to a function to create a signature
	 */
	iot_error_t (*sign)(iot_crypto_pk_context_t *ctx,
				unsigned char *input, size_t ilen,
				unsigned char *sig, size_t *slen);
	/**
	 * @brief a pointer to a function to verify a signature
	 */
	iot_error_t (*verify)(iot_crypto_pk_context_t *ctx,
				unsigned char *input, size_t ilen,
				unsigned char *sig, size_t slen);
} iot_crypto_pk_funcs_t;

/**
 * @brief Contains key pair information and public key based function lists.
 */
struct iot_crypto_pk_context {
	iot_crypto_pk_info_t *info;	/** @brief a pointer to a key pair info */
	const iot_crypto_pk_funcs_t *fn;/** @brief a pointer to a function lists */
};

/**
 * @brief Contains public and private keys for Ed25519
 */
struct iot_crypto_keypair {
	unsigned char *pubkey;		/** @brief a pointer to a public key */
	unsigned char *seckey;		/** @brief a pointer to a private key */
};

/**
 * @brief Contains Ed25519 and Curve25519 key pairs
 */
typedef struct iot_crypto_ed25519_keypair {
	/**
	 * @brief a pointer to a Ed25519 key pair for signature
	 */
	struct iot_crypto_keypair sign;
	/**
	 * @brief a pointer to a curve25519 key pair for encryption/decryption
	 */
	struct iot_crypto_keypair curve;
} iot_crypto_ed25519_keypair_t;

/**
 * @brief Contains parameters to share a key between Things and ST apps
 */
typedef struct iot_crypto_ecdh_params {
	/**
	 * @brief a pointer to a things secret key based on curve25519
	 */
	unsigned char *t_seckey;
	/**
	 * @brief a pointer to a server public key based on curve25519
	 */
	unsigned char *s_pubkey;
	/**
	 * @brief a pointer to a random token as a salt
	 */
	unsigned char *hash_token;
	/**
	 * @brief a length of random token
	 */
	size_t hash_token_len;
} iot_crypto_ecdh_params_t;

/**
 * @brief	Initialize a context by passed private key data
 * @param[in]	ctx	a pointer to a buffer to handle crypto context
 * @param[in]	info	a pointer to a buffer containing private key data
 * @retval	IOT_ERROR_NONE	context is sucessfully initialized
 * @retval	IOT_ERROR_CRYPTO_PK_INVALID_CTX	ctx is null
 * @retval	IOT_ERROR_CRYPTO_PK_INVALID_ARG	info is null
 * @retval	IOT_ERROR_CRYPTO_PK_UNKNOWN_KEYTYPE	private key data has
 *		not supported algorithm
 */
iot_error_t iot_crypto_pk_init(iot_crypto_pk_context_t *ctx,
                               iot_crypto_pk_info_t *info);

/**
 * @brief	Cleanup the context
 * @param[in]	ctx	a pointer to a buffer to cleanup
 */
void iot_crypto_pk_free(iot_crypto_pk_context_t *ctx);

/**
 * @brief	Generate a signature
 * @param[in]	ctx	a pointer to a buffer containing crypto context
 * @param[in]	input	a pointer to a buffer to generate a signature
 * @param[in]	ilen	the size of buffer pointed by input in bytes
 * @param[out]	sig	a pointer to a buffer to store a signature
 * @param[out]	slen	the bytes written to sig
 * @retval	IOT_ERROR_NONE	the signature is sucessfully generated
 * @retval	IOT_ERROR_CRYPTO_PK_PARSEKEY	failed to parse device certificate
 * @retval	IOT_ERROR_CRYPTO_PK_INVALID_CTX	ctx is null
 * @retval	IOT_ERROR_CRYPTO_PK_INVALID_ARG	info is null
 * @retval	IOT_ERROR_CRYPTO_PK_INVALID_KEYLEN	a length of private key is
 *		wrong
 * @retval	IOT_ERROR_CRYPTO_PK_SIGN	failed to generate signature
 */
iot_error_t iot_crypto_pk_sign(iot_crypto_pk_context_t *ctx,
                               unsigned char *input, size_t ilen,
                               unsigned char *sig, size_t *slen);

/**
 * @brief	Verify the signature
 * @param[in]	ctx	a pointer to a buffer containing crypto context
 * @param[in]	input	a pointer to a buffer to generate a signature
 * @param[in]	ilen	the size of buffer pointed by input in bytes
 * @param[in]	sig	a pointer to a buffer containing the signature
 * @param[in]	slen	the size of buffer pointed by sig in bytes
 * @retval	IOT_ERROR_NONE	the signature is sucessfully verified
 * @retval	IOT_ERROR_CRYPTO_PK_NULL_FUNC	verify function is not implemented
 * @retval	IOT_ERROR_CRYPTO_PK_PARSEKEY	failed to parse device certificate
 * @retval	IOT_ERROR_CRYPTO_PK_INVALID_CTX	ctx is null
 * @retval	IOT_ERROR_CRYPTO_PK_INVALID_ARG	info is null
 * @retval	IOT_ERROR_CRYPTO_PK_INVALID_KEYLEN	a length of private key is
 *		wrong
 * @retval	IOT_ERROR_CRYPTO_PK_VERIFY	the signature is mismatched
 */
iot_error_t iot_crypto_pk_verify(iot_crypto_pk_context_t *ctx,
                                 unsigned char *input, size_t ilen,
                                 unsigned char *sig, size_t slen);

/**
 * @brief	Prepare a buffer to store the ed25519 and curve25519 keypair
 * @param[in]	kp	a pointer to a structure of the keypair buffers
 * @retval	IOT_ERROR_NONE		the buffer is sucessfully allocated
 * @retval	IOT_ERROR_MEM_ALLOC	failed to alloc buffer for keypair
 */
iot_error_t iot_crypto_ed25519_init_keypair(
			iot_crypto_ed25519_keypair_t *kp);

/**
 * @brief	Cleanup the buffer that allocated for keypair
 * @param[in]	kp	a pointer to a structure of the keypair to cleanup
 */
void iot_crypto_ed25519_free_keypair(
			iot_crypto_ed25519_keypair_t *kp);

/**
 * @brief	Converts an ed25519 keypair to an x25519 keypair
 * @param[in]	kp	a pointer to a structure of the keypair buffers
 *		ed25519 keypair should be prepared
 * @retval	IOT_ERROR_NONE	the buffer is sucessfully allocated
 * @retval	IOT_ERROR_CRYPTO_ED_KEY_CONVERT failed to convert to x25519
 */
iot_error_t iot_crypto_ed25519_convert_keypair(
			iot_crypto_ed25519_keypair_t *kp);

/**
 * @brief	Converts an ed25519 public key to an x25519 public key
 * @param[in]	ed25519_key	a pointer to a public key buffer
 * @param[out]	curve25519_key	a pointer to a buffer to store converted
 *		x25519 public key
 * @retval	IOT_ERROR_NONE	the buffer is sucessfully allocated
 * @retval	IOT_ERROR_CRYPTO_ED_KEY_CONVERT failed to convert to x25519
 */
iot_error_t iot_crypto_ed25519_convert_pubkey(unsigned char *ed25519_key,
					unsigned char *curve25519_key);

/**
 * @brief	Converts an ed25519 secret key to an x25519 secret key
 * @param[in]	ed25519_key	a pointer to a secret key buffer
 * @param[out]	curve25519_key	a pointer to a buffer to store converted
 *		x25519 secret key
 * @retval	IOT_ERROR_NONE	the buffer is sucessfully allocated
 * @retval	IOT_ERROR_CRYPTO_ED_KEY_CONVERT failed to convert to x25519
 */
iot_error_t iot_crypto_ed25519_convert_seckey(unsigned char *ed25519_key,
					unsigned char *curve25519_key);

/**
 * @brief	Generate a master secret
 * @details	This function generates a master secret by combining
 *		the shared key and the hashed token.
 *		The shared key is generated by ECDH using device's x25519
 *		private key and peer's x25519 public key.
 *		The hashed token is shared by peer.
 * @param[out]	master	a pointer to a buffer to store master secret
 * @param[in]	mlen	the size of buffer pointed by master in bytes
 * @param[in]	params	a pointer to a buffer containing the private key,
 *		public key and hashed token to generate master secret
 * @retval	IOT_ERROR_NONE	the master secret is sucessfully generated
 * @retval	IOT_ERROR_INVALID_ARGS	params has invalid data
 * @retval	IOT_ERROR_MEM_ALLOC	failed to alloc buffer for shared key
 * @retval	IOT_ERROR_CRYPTO_PK_ECDH	failed in ECDH processing
 * @retval	IOT_ERROR_CRYPTO_ED_KEY_CONVERT failed to convert to x25519
 */
iot_error_t iot_crypto_ecdh_gen_master_secret(unsigned char *master,
			size_t mlen, iot_crypto_ecdh_params_t *params);

/*
 * Symmetric Key based operations
 */

/**
 * @brief Types of supported cipher algorithms
 */
typedef enum {
	IOT_CRYPTO_CIPHER_AES256,
	IOT_CRYPTO_CIPHER_UNKNOWN,
} iot_crypto_cipher_type_t;

/**
 * @brief Types of cipher operations
 */
typedef enum {
	IOT_CRYPTO_CIPHER_DECRYPT,
	IOT_CRYPTO_CIPHER_ENCRYPT,
} iot_crypto_cipher_mode_t;

/**
 * @brief Contains cipher informations
 */
typedef struct iot_crypto_cipher_info {
	/**
	 * @brief type of cipher algorithm
	 */
	iot_crypto_cipher_type_t type;
	/**
	 * @brief mode of cipher operation
	 */
	iot_crypto_cipher_mode_t mode;
	/**
	 * @brief a pointer to a shared key
	 */
	unsigned char *key;
	/**
	 * @brief a pointer to a IV for AES cipher
	 */
	unsigned char *iv;
	/**
	 * @brief a length of a shared key
	 */
	size_t key_len;
	/**
	 * @brief a length of a IV
	 */
	size_t iv_len;
} iot_crypto_cipher_info_t;

/**
 * @brief	Calculate the required align size that contains
 *		the encrypted data for the input size
 * @details	the size of data to encrypt should be aligned when AES is
 *		used because AES is operated based on block.
 * @param[in]	type	cipher type
 * @param[in]	size	the size of data to encrypt
 * @retval	return the aligned size
 * @retval	return '0' when error occurs
 */
size_t iot_crypto_cipher_get_align_size(iot_crypto_cipher_type_t type,
			size_t size);

/**
 * @brief	Generic encryption/decryption function
 * @details	Supported cipher algorithms is AES-256 CBC mode
 * @param[in]	info	a pointer to a buffer containing cipher context
 * @param[in]	input	a pointer to a buffer to encrypt/decrypt
 * @param[in]	ilen	the size of buffer pointed by input in bytes
 * @param[out]	out	a pointer to a buffer to store a signature
 * @param[out]	olen	the bytes written to out
 * @param[in]	osize	the size of buffer pointed by out in bytes
 * @retval	IOT_ERROR_NONE	encryption/decryption is a success
 * @retval	IOT_ERROR_CRYPTO_CIPHER_UNKNOWN_TYPE not supported cipher is
 *		requested.
 * @retval	IOT_ERROR_CRYPTO_CIPHER failed while encrypting/decrypting
 */
iot_error_t iot_crypto_cipher_aes(iot_crypto_cipher_info_t *info,
			unsigned char *input, size_t ilen,
			unsigned char *out, size_t *olen, size_t osize);

/**
 * @brief	Encryption of the input data
 * @details	The encryption key is generated from device unique value
 * @param[in]	input	a pointer to a buffer to encrypt
 * @param[in]	ilen	the size of buffer pointed by input in bytes
 * @param[out]	output	a pointer of pointer to a buffer to store the
 *		encrypted data
 * @param[out]	olen	the bytes written to output buffer
 * @retval	IOT_ERROR_NONE encryption is success
 * @retval	IOT_ERROR_MEM_ALLOC mem alloc failed for output buffer
 * @retval	IOT_ERROR_CRYPTO_CIPHER_ALIGN failed to get align size
 *		of the input size for output buffer
 * @retval	IOT_ERROR_CRYPTO_CIPHER cipher operation is failed
 * @retval	IOT_ERROR_CRYPTO_SS_KDF failed during derivate the key
 */
iot_error_t iot_crypto_ss_encrypt(unsigned char *input, size_t ilen,
				unsigned char **output, size_t *olen);

/**
 * @brief	Decryption of the input data
 * @details	The decryption key is generated from device unique value
 * @param[in]	input	a pointer to a buffer to decrypt
 * @param[in]	ilen	the size of buffer pointed by input in bytes
 * @param[out]	output	a pointer of pointer to a buffer to store the
 *		decrypted data
 * @param[out]	olen	the bytes written to output buffer
 * @retval	IOT_ERROR_NONE decryption is success
 * @retval	IOT_ERROR_MEM_ALLOC mem alloc failed for output buffer
 * @retval	IOT_ERROR_CRYPTO_CIPHER_ALIGN failed to get align size
 *		of the input size for output buffer
 * @retval	IOT_ERROR_CRYPTO_CIPHER_UNKNOWN_TYPE cipher is requested
 *		with not supported algorithm
 * @retval	IOT_ERROR_CRYPTO_CIPHER cipher operation is failed
 * @retval	IOT_ERROR_CRYPTO_SS_KDF failed during derivate the key
 */
iot_error_t iot_crypto_ss_decrypt(unsigned char *input, size_t ilen,
				unsigned char **output, size_t *olen);

#ifdef __cplusplus
}
#endif

#endif /* _IOT_CRYPTO_H_ */
