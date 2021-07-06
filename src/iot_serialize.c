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

#include <cbor.h>

#include "iot_debug.h"
#include "iot_error.h"
#include "iot_internal.h"
#include "JSON.h"

#include <inttypes.h>
#include "compilersupport_p.h"

static CborError _iot_cbor_value_to_json(CborValue *it, char *out, size_t len, size_t *olen);

static CborError _iot_cbor_array_to_json(CborValue *it, char *out, size_t len, size_t *olen)
{
	CborError err;
	char comma = 0;
	size_t n = 0;
	int c = 0;

	while (!cbor_value_at_end(it)) {
		if (comma) {
			out[c++] = comma;
		} else {
			comma = ',';
		}

		err = _iot_cbor_value_to_json(it, out + c, len - c, &n);
		if (err) {
			return err;
		}

		c += (int)n;
	}

	*olen = (size_t)c;

	return CborNoError;
}

static CborError _iot_cbor_map_to_json(CborValue *it, char *out, size_t len, size_t *olen)
{
	CborError err;
	CborType key_type;
	char comma = 0;
	char *key;
	size_t n = 0;
	int c = 0;

	while (!cbor_value_at_end(it)) {
		if (comma) {
			out[c++] = comma;
		} else {
			comma = ',';
		}

		key_type = cbor_value_get_type(it);
		if (key_type != CborTextStringType) {
			return CborErrorJsonObjectKeyNotString;
		}

		/* key */
		err = cbor_value_dup_text_string(it, &key, &n, it);
		if (err) {
			return err;
		}

		c += snprintf(out + c, len - c, "\"%s\":", key);
		free(key);

		/* value */
		err = _iot_cbor_value_to_json(it, out + c, len - c, &n);
		c += (int)n;

		if (err) {
			return err;
		}
	}

	*olen = (size_t)c;

	return CborNoError;
}

static CborError _iot_cbor_value_to_json(CborValue *it, char *out, size_t len, size_t *olen)
{
	CborError err;
	CborType type;
	CborValue recursed;
	char *str;
	int c = 0;
	size_t n = 0;
	uint64_t val_i64;
	double val_dbl;
	bool val_bool;
#if !IOT_SERIALIZE_SPRINTF_FLOAT
	double intpart, fracpart;
#endif

	type = cbor_value_get_type(it);

	switch (type) {
	case CborArrayType:
	case CborMapType:
		err = cbor_value_enter_container(it, &recursed);
		if (err) {
			it->ptr = recursed.ptr;
			return err;
		}

		c += snprintf(out + c, len - c, "%c", type == CborArrayType ? '[' : '{');

		if (type == CborArrayType)
			err = _iot_cbor_array_to_json(&recursed, out + c, len - c, &n);
		else
			err = _iot_cbor_map_to_json(&recursed, out + c, len - c, &n);

		if (err) {
			it->ptr = recursed.ptr;
			return err;
		}

		c += (int)n;

		c += snprintf(out + c, len - c, "%c", type == CborArrayType ? ']' : '}');

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

		c += snprintf(out + c, len - c, "\"%s\"", str);
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

		c += snprintf(out + c, len - c, "%d", (int)val_dbl);

		break;
	case CborDoubleType:
		cbor_value_get_double(it, &val_dbl);

		if (fpclassify(val_dbl) < 0) {
			return CborErrorIO;
		}
#if IOT_SERIALIZE_SPRINTF_FLOAT
		val_i64 = (uint64_t)fabs(val_dbl);
		if ((double)val_i64 == fabs(val_dbl)) {
			/* print as integer so we get the full precision */
			c += snprintf(out + c, len - c, "%s%" PRIu64, val_dbl < 0 ? "-" : "", val_i64);
		} else {
			/* this number is definitely not a 64-bit integer */
			c += snprintf(out + c, len - c, "%." DBL_DECIMAL_DIG_STR "g", val_dbl);
		}
#else
		fracpart = modf(val_dbl, &intpart);
		c += snprintf(out + c, len - c, "%d", (int)intpart);
		if (fracpart != 0) {
			c += snprintf(out + c, len - c, ".");
			fracpart = round(fracpart * IOT_SERIALIZE_DECIMAL_PRECISION) / IOT_SERIALIZE_DECIMAL_PRECISION;
			if (fracpart < 0) {
				fracpart *= -1;
			}
			while(fracpart != (int)fracpart) {
				fracpart *= 10;
				c += snprintf(out + c, len - c, "%d", ((int)fracpart) % 10);
			}
		}
#endif

		break;
	case CborTagType:
		{
			CborTag result;
			err = cbor_value_get_tag(it, &result);
			if (err) {
				return err;
			}
			switch(result)
			{
				/* Cbor Decimal Tag type has 2 array values exponent and mantissa */
				case CborDecimalTag:
					{
						uint64_t exp, man;
						bool man_sign;
						err = cbor_value_advance_fixed(it);
						if (err) {
							return err;
						}
						err = cbor_value_enter_container(it, &recursed);
						if (err) {
							return err;
						}
						cbor_value_get_raw_integer(&recursed, &exp);
						exp = pow(10, (uint32_t)exp);
						err = cbor_value_advance_fixed(&recursed);
						if (err) {
							return err;
						}
						cbor_value_get_raw_integer(&recursed, &man);
						man_sign = cbor_value_is_negative_integer(&recursed);

						err = cbor_value_advance_fixed(&recursed);
						if (err) {
							return err;
						}
						err = cbor_value_leave_container(it, &recursed);
						if (err) {
							return err;
						}

						/* mantissa is negative */
						if (man_sign)
						{
							c += snprintf(out + c, len - c, "-");
						}

						c += snprintf(out + c, len - c, "%u", (uint32_t)(man/exp));
						c += snprintf(out + c, len - c, ".");
						if (exp > IOT_SERIALIZE_DECIMAL_PRECISION)
							c += snprintf(out + c, len - c, "%u",
									(uint32_t)((man%exp)/(exp/IOT_SERIALIZE_DECIMAL_PRECISION)));
						else
							c += snprintf(out + c, len - c, "%u", (uint32_t)(man%exp));

						*olen = (size_t)c;
						return CborNoError;
					}
					break;
				default:
					return CborErrorUnknownType;
			}
		}
		break;
	case CborBooleanType:
		err = cbor_value_get_boolean(it, &val_bool);
		if (err)
		{
			return err;
		}

		if (val_bool)
		{
			c += snprintf(out + c, len -c, "%s", "true");
		}
		else
		{
			c += snprintf(out + c, len -c, "%s", "false");
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

	len = cborlen * 2;
	buf = (char *)malloc(len);
	if (!buf) {
		IOT_ERROR("malloc failed for json");
		return IOT_ERROR_MEM_ALLOC;
	}

	memset(buf, 0, len);

	err = _iot_cbor_value_to_json(&it, buf, len, &olen);
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

static CborError _iot_json_value_to_cbor(JSON_H *json, CborEncoder *cbor)
{
	CborError err = 0;

	if (JSON_IS_OBJECT(json)) {
		CborEncoder d = {0};
		char *string;
		cbor_encoder_create_map(cbor, &d, CborIndefiniteLength);
		JSON_H *child = JSON_GET_CHILD_ITEM(json);
		while (child) {
			string = JSON_GET_OBJECT_ITEM_STRING(child);
			err = cbor_encode_text_stringz(&d, string);
			if (err != 0 && err != CborErrorOutOfMemory) {
				return err;
			}
			err = _iot_json_value_to_cbor(child, &d);
			if (err != 0 && err != CborErrorOutOfMemory) {
				return err;
			}

			child = JSON_GET_NEXT_ITEM(child);
		}
		cbor_encoder_close_container_checked(cbor, &d);
	} else if (JSON_IS_STRING(json)) {
		char *string;
		string = JSON_GET_STRING_VALUE(json);
		err = cbor_encode_text_stringz(cbor, string);
		if (err != 0 && err != CborErrorOutOfMemory) {
			return err;
		}
	} else if (JSON_IS_ARRAY(json)) {
		CborEncoder d = {0};
		cbor_encoder_create_array(cbor, &d, CborIndefiniteLength);
		JSON_H *child = JSON_GET_CHILD_ITEM(json);
		while (child) {
			err = _iot_json_value_to_cbor(child, &d);
			if (err != 0 && err != CborErrorOutOfMemory) {
				return err;
			}

			child = JSON_GET_NEXT_ITEM(child);
		}
		cbor_encoder_close_container_checked(cbor, &d);
	} else if (JSON_IS_NUMBER(json)) {
		double number = JSON_GET_NUMBER_VALUE(json);
		double intpart;
		if (modf(number, &intpart) == 0) {
			err = cbor_encode_int(cbor, (int)number);
		} else {
			err = cbor_encode_double(cbor, number);
		}
		if (err != 0 && err != CborErrorOutOfMemory) {
			return err;
		}
	} else if (JSON_IS_BOOL(json)) {
		bool isTrue = JSON_IS_TRUE(json);
		err = cbor_encode_boolean(cbor, isTrue);
		if (err != 0 && err != CborErrorOutOfMemory) {
			return err;
		}
	} else {
		IOT_ERROR("not supporting type");
		return CborUnknownError;
	}

	return err;
}

iot_error_t iot_serialize_json2cbor(JSON_H *json, uint8_t **cbor, size_t *cborlen)
{
	CborError err;
	CborEncoder root = {0};
	uint8_t *buf;
	size_t olen = 128, actual_len;
	size_t extra_bytes_needed = 0;

	if ((cbor == NULL) || (cborlen == NULL) ||
	    (json == NULL)) {
		IOT_ERROR("invalid params");
		return IOT_ERROR_INVALID_ARGS;
	}

retry:
	olen += extra_bytes_needed;
	buf = (uint8_t *)iot_os_malloc(olen + 1);
	if (buf == NULL) {
		IOT_ERROR("failed to malloc for cbor");
		return IOT_ERROR_MEM_ALLOC;
	}
	memset(buf, 0, olen + 1);

	cbor_encoder_init(&root, buf, olen, 0);

	err = _iot_json_value_to_cbor(json, &root);
	if (err != 0 && err != CborErrorOutOfMemory) {
		IOT_ERROR("fail serialize to cbor");
		goto exit_failed;
	}

	extra_bytes_needed = cbor_encoder_get_extra_bytes_needed(&root);
	if (extra_bytes_needed) {
		IOT_WARN("allocated size is not enough need more %d", extra_bytes_needed);
		free(buf);
		goto retry;
	}

	actual_len = cbor_encoder_get_buffer_size(&root, buf);
	if (actual_len < olen) {
		uint8_t *tmp = (uint8_t *)realloc(buf, actual_len + 1);
		if (!tmp) {
			IOT_ERROR("realloc failed for cbor");
			goto exit_failed;
		} else {
			buf = tmp;
		}
	}

	*cbor = buf;
	*cborlen = actual_len;

	return 0;

exit_failed:
	free(buf);

	return IOT_ERROR_BAD_REQ;
}
