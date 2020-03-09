/* ***************************************************************************
 *
 * Copyright 2020 Samsung Electronics All Rights Reserved.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include <cJSON.h>
#include <cbor.h>

#include "iot_debug.h"
#include "iot_error.h"
#include "iot_internal.h"

#include <inttypes.h>
#include "compilersupport_p.h"

static CborError _iot_cbor_value_to_json(CborValue *it, char *out, size_t *olen);

static CborError _iot_cbor_array_to_json(CborValue *it, char *out, size_t *olen)
{
	CborError err;
	const char *comma = "";
	size_t n = 0;
	int c = 0;

	while (!cbor_value_at_end(it)) {
		c += sprintf(out + c, "%s", comma);
		comma = ",";

		err = _iot_cbor_value_to_json(it, out + c, &n);
		if (err) {
			return err;
		}

		c += (int)n;
	}

	*olen = (size_t)c;

	return CborNoError;
}

static CborError _iot_cbor_map_to_json(CborValue *it, char *out, size_t *olen)
{
	CborError err;
	CborType key_type;
	const char *comma = "";
	char *key;
	size_t n = 0;
	int c = 0;

	while (!cbor_value_at_end(it)) {
		c += sprintf(out + c, "%s", comma);
		comma = ",";

		key_type = cbor_value_get_type(it);
		if (key_type != CborTextStringType) {
			return CborErrorJsonObjectKeyNotString;
		}

		/* key */
		err = cbor_value_dup_text_string(it, &key, &n, it);
		if (err) {
			return err;
		}

		c += sprintf(out + c, "\"%s\":", key);
		free(key);

		/* value */
		err = _iot_cbor_value_to_json(it, out + c, &n);
		c += (int)n;

		if (err) {
			return err;
		}
	}

	*olen = (size_t)c;

	return CborNoError;
}

static CborError _iot_cbor_value_to_json(CborValue *it, char *out, size_t *olen)
{
	CborError err;
	CborType type;
	CborValue recursed;
	char *str;
	int c = 0;
	size_t n = 0;
	uint64_t val_i64;
	double val_dbl;

	type = cbor_value_get_type(it);

	switch (type) {
	case CborArrayType:
	case CborMapType:
		err = cbor_value_enter_container(it, &recursed);
		if (err) {
			it->ptr = recursed.ptr;
			return err;
		}

		c += sprintf(out + c, "%c", type == CborArrayType ? '[' : '{');

		if (type == CborArrayType)
			err = _iot_cbor_array_to_json(&recursed, out + c, &n);
		else
			err = _iot_cbor_map_to_json(&recursed, out + c, &n);

		if (err) {
			it->ptr = recursed.ptr;
			return err;
		}

		c += (int)n;

		c += sprintf(out + c, "%c", type == CborArrayType ? ']' : '}');

		err = cbor_value_leave_container(it, &recursed);
		if (err) {
			return err;
		}

		*olen = (size_t)c;

		return CborNoError;
	case CborByteStringType:
	case CborTextStringType:
		err = cbor_value_dup_text_string(it, &str, &n, it);
		if (err) {
			return err;
		}

		c += sprintf(out + c, "\"%s\"", str);
		free(str);

		*olen = (size_t)c;

		return CborNoError;
	case CborIntegerType:
		cbor_value_get_raw_integer(it, &val_i64);
		val_dbl = (double)val_i64;

		if (cbor_value_is_negative_integer(it)) {
			/* convert to negative */
			val_dbl = -val_dbl - 1;
		}

		c += sprintf(out + c, "%.0f", val_dbl);

		break;
	case CborDoubleType:
		cbor_value_get_double(it, &val_dbl);

		if (fpclassify(val_dbl) < 0) {
			return CborErrorIO;
		}

		val_i64 = (uint64_t)fabs(val_dbl);
		if ((double)val_i64 == fabs(val_dbl)) {
			/* print as integer so we get the full precision */
			c += sprintf(out + c, "%s%" PRIu64, val_dbl < 0 ? "-" : "", val_i64);
		} else {
			/* this number is definitely not a 64-bit integer */
			c += sprintf(out + c, "%." DBL_DECIMAL_DIG_STR "g", val_dbl);
		}

		break;
	default:
		return CborErrorUnknownType;
	}

	*olen = (size_t)c;

	return cbor_value_advance_fixed(it);
}

iot_error_t iot_serialize_cbor2json(uint8_t *cbor, size_t cborlen, char **json, size_t *jsonlen)
{
	CborParser parser;
	CborValue it;
	CborError err;
	char *buf;
	char *tmp;
	size_t len;
	size_t olen = 0;

	if ((cbor == NULL) || (cborlen == 0) ||
	    (json == NULL) || (jsonlen == NULL)) {
		IOT_ERROR("invalid cbor");
		return IOT_ERROR_INVALID_ARGS;
	}

	IOT_DEBUG("cbor 0x%x@%p", (int)cborlen, cbor);

	err = cbor_parser_init(cbor, cborlen, 0, &parser, &it);
	if (err) {
		IOT_ERROR("cbor_parser_init = %d", err);
		return IOT_ERROR_CBOR_PARSE;
	}

	len = cborlen * 4 / 3;
	buf = (char *)malloc(len);
	if (!buf) {
		IOT_ERROR("malloc failed for json");
		return IOT_ERROR_MEM_ALLOC;
	}

	memset(buf, 0, len);

	err = _iot_cbor_value_to_json(&it, buf, &olen);
	if (err) {
		IOT_ERROR("_iot_cbor_value_to_json_advance = %d", err);
		free(buf);
		return IOT_ERROR_CBOR_TO_JSON;
	}

	if (olen < len) {
		tmp = (char *)realloc(buf, olen + 1);
		if (!tmp) {
			IOT_WARN("realloc failed for json, use origin");
		} else {
			buf = tmp;
		}
	} else {
		IOT_ERROR("allocated size is not enough (%d < %d)",
				(int)len, (int)olen);
		free(buf);
		return IOT_ERROR_MEM_ALLOC;
	}

	*json = buf;
	*jsonlen = olen;

	IOT_DEBUG("json 0x%x@%p", (int)*jsonlen, *json);

	return IOT_ERROR_NONE;
}
