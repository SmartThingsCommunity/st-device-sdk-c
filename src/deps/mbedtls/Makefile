include $(TOPDIR)/make/common.mk

SRCDIR = mbedtls/library
PREFIX := mbedtls_

LOCAL_CFLAGS := -Imbedtls/include -Iport/posix/include

LOCAL_CFLAGS += -Wall -W -Wdeclaration-after-statement
LOCAL_CFLAGS += -D_FILE_OFFSET_BITS=64
LOCAL_CFLAGS += -DMBEDTLS_CONFIG_FILE='"mbedtls/posix_config.h"'

OBJS_CRYPTO=	aes.o		aesni.o		arc4.o		\
		aria.o		asn1parse.o	asn1write.o	\
		base64.o	bignum.o	blowfish.o	\
		camellia.o	ccm.o		chacha20.o	\
		chachapoly.o	cipher.o	cipher_wrap.o	\
		cmac.o		ctr_drbg.o	des.o		\
		dhm.o		ecdh.o		ecdsa.o		\
		ecjpake.o	ecp.o				\
		ecp_curves.o	entropy.o	entropy_poll.o	\
		error.o		gcm.o		havege.o	\
		hkdf.o						\
		hmac_drbg.o	md.o		md2.o		\
		md4.o		md5.o		md_wrap.o	\
		memory_buffer_alloc.o		nist_kw.o	\
		oid.o		padlock.o	pem.o		\
		pk.o		pk_wrap.o	pkcs12.o	\
		pkcs5.o		pkparse.o	pkwrite.o	\
		platform.o	platform_util.o	poly1305.o	\
		ripemd160.o	rsa_internal.o	rsa.o  		\
		sha1.o		sha256.o	sha512.o	\
		threading.o	timing.o	version.o	\
		version_features.o		xtea.o

OBJS_X509=	certs.o		pkcs11.o	x509.o		\
		x509_create.o	x509_crl.o	x509_crt.o	\
		x509_csr.o	x509write_crt.o	x509write_csr.o

OBJS_TLS=	debug.o		net_sockets.o		\
		ssl_cache.o	ssl_ciphersuites.o	\
		ssl_cli.o	ssl_cookie.o		\
		ssl_srv.o	ssl_ticket.o		\
		ssl_tls.o

OBJS = $(addprefix $(SRCDIR)/,$(OBJS_CRYPTO) $(OBJS_X509) $(OBJS_TLS))

all: $(OBJS)

clean:
	@rm -f $(OBJS)

.PHONY: clean
