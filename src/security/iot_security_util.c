/* ***************************************************************************
 *
 * Copyright (c) 2020 Samsung Electronics All Rights Reserved.
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

#include "iot_debug.h"
#include "security/iot_security_util.h"
#include "port_crypto.h"

/* base64.c from mbedtls */

static const unsigned char base64_enc_map[64] =
{
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
    'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
    'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd',
    'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
    'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', '+', '/'
};

static const unsigned char base64_dec_map[128] =
{
    127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
    127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
    127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
    127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
    127, 127, 127,  62, 127, 127, 127,  63,  52,  53,
     54,  55,  56,  57,  58,  59,  60,  61, 127, 127,
    127,  64, 127, 127, 127,   0,   1,   2,   3,   4,
      5,   6,   7,   8,   9,  10,  11,  12,  13,  14,
     15,  16,  17,  18,  19,  20,  21,  22,  23,  24,
     25, 127, 127, 127, 127, 127, 127,  26,  27,  28,
     29,  30,  31,  32,  33,  34,  35,  36,  37,  38,
     39,  40,  41,  42,  43,  44,  45,  46,  47,  48,
     49,  50,  51, 127, 127, 127, 127, 127
};

#define BASE64_SIZE_T_MAX   ( (size_t) -1 ) /* SIZE_T_MAX is not standard */

/*
 * Decode a base64-formatted buffer, copid from mbedtls_base64_decode
 */
static int _base64_decode( unsigned char *dst, size_t dlen, size_t *olen,
                   const unsigned char *src, size_t slen )
{
    size_t i, n;
    uint32_t j, x;
    unsigned char *p;

    /* First pass: check for validity and get output length */
    for( i = n = j = 0; i < slen; i++ )
    {
        /* Skip spaces before checking for EOL */
        x = 0;
        while( i < slen && src[i] == ' ' )
        {
            ++i;
            ++x;
        }

        /* Spaces at end of buffer are OK */
        if( i == slen )
            break;

        if( ( slen - i ) >= 2 &&
            src[i] == '\r' && src[i + 1] == '\n' )
            continue;

        if( src[i] == '\n' )
            continue;

        /* Space inside a line is an error */
        if( x != 0 )
            return( -1 );

        if( src[i] == '=' && ++j > 2 )
            return( -1 );

        if( src[i] > 127 || base64_dec_map[src[i]] == 127 )
            return( -1 );

        if( base64_dec_map[src[i]] < 64 && j != 0 )
            return( -1 );

        n++;
    }

    if( n == 0 )
    {
        *olen = 0;
        return( 0 );
    }

    /* The following expression is to calculate the following formula without
     * risk of integer overflow in n:
     *     n = ( ( n * 6 ) + 7 ) >> 3;
     */
    n = ( 6 * ( n >> 3 ) ) + ( ( 6 * ( n & 0x7 ) + 7 ) >> 3 );
    n -= j;

    if( dst == NULL || dlen < n )
    {
        *olen = n;
        return( -1 );
    }

   for( j = 3, n = x = 0, p = dst; i > 0; i--, src++ )
   {
        if( *src == '\r' || *src == '\n' || *src == ' ' )
            continue;

        j -= ( base64_dec_map[*src] == 64 );
        x  = ( x << 6 ) | ( base64_dec_map[*src] & 0x3F );

        if( ++n == 4 )
        {
            n = 0;
            if( j > 0 ) *p++ = (unsigned char)( x >> 16 );
            if( j > 1 ) *p++ = (unsigned char)( x >>  8 );
            if( j > 2 ) *p++ = (unsigned char)( x       );
        }
    }

    *olen = p - dst;

    return( 0 );
}

/*
 * Encode a buffer into base64 format, copied from mbedtls_base64_encode
 */
int _base64_encode( unsigned char *dst, size_t dlen, size_t *olen,
                   const unsigned char *src, size_t slen )
{
    size_t i, n;
    int C1, C2, C3;
    unsigned char *p;

    if( slen == 0 )
    {
        *olen = 0;
        return( 0 );
    }

    n = slen / 3 + ( slen % 3 != 0 );

    if( n > ( BASE64_SIZE_T_MAX - 1 ) / 4 )
    {
        *olen = BASE64_SIZE_T_MAX;
        return( -1 );
    }

    n *= 4;

    if( ( dlen < n + 1 ) || ( NULL == dst ) )
    {
        *olen = n + 1;
        return( -1 );
    }

    n = ( slen / 3 ) * 3;

    for( i = 0, p = dst; i < n; i += 3 )
    {
        C1 = *src++;
        C2 = *src++;
        C3 = *src++;

        *p++ = base64_enc_map[(C1 >> 2) & 0x3F];
        *p++ = base64_enc_map[(((C1 &  3) << 4) + (C2 >> 4)) & 0x3F];
        *p++ = base64_enc_map[(((C2 & 15) << 2) + (C3 >> 6)) & 0x3F];
        *p++ = base64_enc_map[C3 & 0x3F];
    }

    if( i < slen )
    {
        C1 = *src++;
        C2 = ( ( i + 1 ) < slen ) ? *src++ : 0;

        *p++ = base64_enc_map[(C1 >> 2) & 0x3F];
        *p++ = base64_enc_map[(((C1 & 3) << 4) + (C2 >> 4)) & 0x3F];

        if( ( i + 1 ) < slen )
             *p++ = base64_enc_map[((C2 & 15) << 2) & 0x3F];
        else *p++ = '=';

        *p++ = '=';
    }

    *olen = p - dst;
    *p = 0;

    return( 0 );
}

/* base64.c from mbedtls */

static iot_error_t _iot_security_url_encode(char *buf, size_t buf_len)
{
	size_t i;

	if (!buf) {
		IOT_ERROR("buf is null");
		IOT_ERROR_DUMP_AND_RETURN(INVALID_ARGS, 0);
	}

	if (!buf_len) {
		IOT_ERROR("length is zero");
		IOT_ERROR_DUMP_AND_RETURN(INVALID_ARGS, 0);
	}

	for (i = 0; i < buf_len; i++) {
		switch (buf[i]) {
		case '+':
			buf[i] = '-';
			break;
		case '/':
			buf[i] = '_';
			break;
		default:
			break;
		}
	}

	return IOT_ERROR_NONE;
}

static iot_error_t _iot_security_url_decode(char *buf, size_t buf_len)
{
	size_t i;

	if (!buf) {
		IOT_ERROR("buf is null");
		IOT_ERROR_DUMP_AND_RETURN(INVALID_ARGS, 0);
	}

	if (!buf_len) {
		IOT_ERROR("length is zero");
		IOT_ERROR_DUMP_AND_RETURN(INVALID_ARGS, 0);
	}

	for (i = 0; i < buf_len; i++) {
		switch (buf[i]) {
		case '-':
			buf[i] = '+';
			break;
		case '_':
			buf[i] = '/';
			break;
		default:
			break;
		}
	}

	return IOT_ERROR_NONE;
}

iot_error_t iot_security_base64_encode(const unsigned char *src, size_t src_len,
                                       unsigned char *dst, size_t dst_len,
                                       size_t *out_len)
{
	int ret;

	if (!src || (src_len == 0)) {
		IOT_ERROR("invalid src with %d@%p", (int)src_len, src);
		IOT_ERROR_DUMP_AND_RETURN(INVALID_ARGS, 0);
	}

	if (!dst || (dst_len == 0)) {
		IOT_ERROR("invalid dst with %d@%p", (int)dst_len, dst);
		IOT_ERROR_DUMP_AND_RETURN(INVALID_ARGS, 0);
	}

	if (!out_len) {
		IOT_ERROR("length output buffer is null");
		IOT_ERROR_DUMP_AND_RETURN(INVALID_ARGS, 0);
	}

	IOT_DEBUG("src: %d@%p, dst: %d@%p", (int)src_len, src, (int)dst_len, dst);

	ret = _base64_encode(dst, dst_len, out_len, src, src_len);
	if (ret) {
		IOT_ERROR("_base64_encode = -0x%04X", -ret);
		IOT_ERROR_DUMP_AND_RETURN(BASE64_ENCODE, -ret);
	}

	IOT_DEBUG("done: %d@%p", (int)*out_len, dst);

	return IOT_ERROR_NONE;
}

iot_error_t iot_security_base64_decode(const unsigned char *src, size_t src_len,
                                       unsigned char *dst, size_t dst_len,
                                       size_t *out_len)
{
	int ret;

	if (!src || (src_len == 0)) {
		IOT_ERROR("invalid src with %d@%p", (int)src_len, src);
		IOT_ERROR_DUMP_AND_RETURN(INVALID_ARGS, 0);
	}

	if (!dst || (dst_len == 0)) {
		IOT_ERROR("invalid dst with %d@%p", (int)dst_len, dst);
		IOT_ERROR_DUMP_AND_RETURN(INVALID_ARGS, 0);
	}

	if (!out_len) {
		IOT_ERROR("length output buffer is null");
		IOT_ERROR_DUMP_AND_RETURN(INVALID_ARGS, 0);
	}

	IOT_DEBUG("src: %d@%p, dst: %d@%p", (int)src_len, src, (int)dst_len, dst);

	ret = _base64_decode(dst, dst_len, out_len, src, src_len);
	if (ret) {
		IOT_ERROR("_base64_decode = -0x%04X", -ret);
		IOT_ERROR_DUMP_AND_RETURN(BASE64_DECODE, -ret);
	}

	IOT_DEBUG("done: %d@%p", (int)*out_len, dst);

	return IOT_ERROR_NONE;
}

iot_error_t iot_security_base64_encode_urlsafe(const unsigned char *src, size_t src_len,
                                               unsigned char *dst, size_t dst_len,
                                               size_t *out_len)
{
	int ret;

	if (!src || (src_len == 0)) {
		IOT_ERROR("invalid src with %d@%p", (int)src_len, src);
		IOT_ERROR_DUMP_AND_RETURN(INVALID_ARGS, 0);
	}

	if (!dst || (dst_len == 0)) {
		IOT_ERROR("invalid dst with %d@%p", (int)dst_len, dst);
		IOT_ERROR_DUMP_AND_RETURN(INVALID_ARGS, 0);
	}

	if (!out_len) {
		IOT_ERROR("length output buffer is null");
		IOT_ERROR_DUMP_AND_RETURN(INVALID_ARGS, 0);
	}

	IOT_DEBUG("src: %d@%p, dst: %d@%p", (int)src_len, src, (int)dst_len, dst);

	ret = _base64_encode(dst, dst_len, out_len, src, src_len);
	if (ret) {
		IOT_ERROR("_base64_encode = -0x%04X", -ret);
		IOT_ERROR_DUMP_AND_RETURN(BASE64_URL_ENCODE, -ret);
	}

	ret = _iot_security_url_encode((char *)dst, *out_len);
	if (ret) {
		IOT_ERROR("_iot_security_url_encode = %d", ret);
		IOT_ERROR_DUMP_AND_RETURN(BASE64_URL_ENCODE, ret);
	}

	IOT_DEBUG("done: %d@%p", (int)*out_len, dst);

	return IOT_ERROR_NONE;
}

iot_error_t iot_security_base64_decode_urlsafe(const unsigned char *src, size_t src_len,
                                             unsigned char *dst, size_t dst_len,
                                             size_t *out_len)
{
	unsigned char *src_dup = NULL;
	size_t align_len;
	size_t i;
	int ret;

	if (!src || (src_len == 0)) {
		IOT_ERROR("invalid src with %d@%p", (int)src_len, src);
		IOT_ERROR_DUMP_AND_RETURN(INVALID_ARGS, 0);
	}

	if (!dst || (dst_len == 0)) {
		IOT_ERROR("invalid dst with %d@%p", (int)dst_len, dst);
		IOT_ERROR_DUMP_AND_RETURN(INVALID_ARGS, 0);
	}

	if (!out_len) {
		IOT_ERROR("length output buffer is null");
		IOT_ERROR_DUMP_AND_RETURN(INVALID_ARGS, 0);
	}

	IOT_DEBUG("src: %d@%p, dst: %d@%p", (int)src_len, src, (int)dst_len, dst);

	align_len = IOT_SECURITY_B64_ALIGN_LEN(src_len);
	src_dup = (unsigned char *)iot_os_malloc(align_len + 1);
	if (src_dup == NULL) {
		IOT_ERROR("malloc failed for align buffer");
		IOT_ERROR_DUMP_AND_RETURN(MEM_ALLOC, 0);
	}

	memcpy(src_dup, src, src_len);
	/* consider '=' removed from tail */
	for (i = src_len; i < align_len; i++) {
		src_dup[i] = '=';
	}
	src_dup[align_len] = '\0';

	ret = _iot_security_url_decode((char *)src_dup, align_len);
	if (ret) {
		IOT_ERROR("_iot_security_url_decode = %d", ret);
		iot_os_free(src_dup);
		IOT_ERROR_DUMP_AND_RETURN(BASE64_URL_DECODE, ret);
	}

	ret = _base64_decode(dst, dst_len, out_len, (const unsigned char *)src_dup, align_len);
	if (ret) {
		IOT_ERROR("_base64_decode = -0x%04X", -ret);
		iot_os_free(src_dup);
		IOT_ERROR_DUMP_AND_RETURN(BASE64_URL_DECODE, -ret);
	}

	iot_os_free(src_dup);
	IOT_DEBUG("done: %d@%p", (int)*out_len, dst);

	return IOT_ERROR_NONE;
}

iot_error_t iot_security_sha512(const unsigned char *input, size_t input_len, unsigned char *output, size_t output_len)
{
	int ret;

	if (!input || (input_len == 0)) {
		IOT_ERROR("invalid input with %d@%p", (int)input_len, input);
		return IOT_ERROR_SECURITY_INVALID_ARGS;
	}

	if (!output || (output_len < 64)) {
		IOT_ERROR("invalid output with %d@%p", (int)output_len, output);
		return IOT_ERROR_SECURITY_INVALID_ARGS;
	}

	ret = port_crypto_sha512(input, input_len, output, output_len);
	if (ret) {
		IOT_ERROR("port_crypto_sha512 ret %04x", ret);
		return ret;
	}

	return IOT_ERROR_NONE;
}

iot_error_t iot_security_sha256(const unsigned char *input, size_t input_len, unsigned char *output, size_t output_len)
{
	int ret;

	if (!input || (input_len == 0)) {
		IOT_ERROR("invalid input with %d@%p", (int)input_len, input);
		return IOT_ERROR_SECURITY_INVALID_ARGS;
	}

	if (!output || (output_len < 32)) {
		IOT_ERROR("invalid output with %d@%p", (int)output_len, output);
		return IOT_ERROR_SECURITY_INVALID_ARGS;
	}

	ret = port_crypto_sha256(input, input_len, output, output_len);
	if (ret) {
		IOT_ERROR("port_crypto_sha256 ret %04x", ret);
		return ret;
	}

	return IOT_ERROR_NONE;
}
