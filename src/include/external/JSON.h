/* ***************************************************************************
 *
 * Copyright (c) 2020-2022 Samsung Electronics All Rights Reserved.
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

#ifndef ST_DEVICE_SDK_C_JSON_H
#define ST_DEVICE_SDK_C_JSON_H

#include <stdbool.h>

#define ST_DEVICE_SDK_C_USE_EXTERNAL_JSON_CJSON
#ifdef ST_DEVICE_SDK_C_USE_EXTERNAL_JSON_CJSON
#include <cJSON.h>
typedef cJSON JSON_H;

static inline JSON_H *JSON_CREATE_OBJECT(void) {
    return cJSON_CreateObject();
}

static inline JSON_H *JSON_GET_OBJECT_ITEM(const JSON_H * const obj, const char * const string) {
    return cJSON_GetObjectItem(obj, string);
}

static inline JSON_H *JSON_GET_CHILD_ITEM(const JSON_H * const obj) {
    return ((cJSON *)obj)->child;
}

static inline JSON_H *JSON_GET_NEXT_ITEM(const JSON_H * const obj) {
    return ((cJSON *)obj)->next;
}

static inline char *JSON_GET_OBJECT_ITEM_STRING(const JSON_H * const obj) {
    return ((cJSON *)obj)->string;
}

static inline double JSON_GET_NUMBER_VALUE(const JSON_H * const item) {
    return ((cJSON *)item)->valuedouble;
}

static inline JSON_H *JSON_DUPLICATE(const JSON_H* item, bool recurse) {
	return cJSON_Duplicate(item, recurse);
}

static inline void JSON_ADD_ITEM_TO_OBJECT(JSON_H *obj, const char *string, JSON_H *item) {
    cJSON_AddItemToObject(obj, string, item);
}

static inline void JSON_ADD_NUMBER_TO_OBJECT(JSON_H * const obj, const char * const name, const double number) {
    cJSON_AddNumberToObject(obj, name, number);
}

static inline void JSON_ADD_STRING_TO_OBJECT(JSON_H * const obj, const char * const name, const char * const string) {
    cJSON_AddStringToObject(obj, name, string);
}

static inline void JSON_ADD_BOOL_TO_OBJECT(JSON_H * const obj, const char * const name, const bool boolean) {
	cJSON_AddBoolToObject(obj, name, boolean);
}

static inline JSON_H *JSON_CREATE_STRING(const char *string) {
    return cJSON_CreateString(string);
}

static inline char *JSON_PRINT(const JSON_H *item) {
    return cJSON_PrintUnformatted(item);
}

static inline void JSON_DELETE(JSON_H *item) {
    cJSON_Delete(item);
}

static inline JSON_H *JSON_CREATE_ARRAY(void) {
    return cJSON_CreateArray();
}

static inline JSON_H *JSON_CREATE_STRING_ARRAY(const char **strings, int count) {
    return cJSON_CreateStringArray(strings, count);
}

static inline void JSON_ADD_ITEM_TO_ARRAY(JSON_H *array, JSON_H *item) {
    cJSON_AddItemToArray(array, item);
}

static inline int JSON_GET_ARRAY_SIZE(const JSON_H *array) {
    return cJSON_GetArraySize(array);
}

static inline JSON_H *JSON_GET_ARRAY_ITEM(const JSON_H *array, int index) {
    return cJSON_GetArrayItem(array, index);
}

static inline JSON_H *JSON_PARSE(const char *value) {
    return cJSON_Parse(value);
}

static inline char *JSON_GET_STRING_VALUE(JSON_H *item) {
    return cJSON_GetStringValue(item);
}

static inline JSON_H *JSON_CREATE_NUMBER(double num) {
    return cJSON_CreateNumber(num);
}

static inline void JSON_FREE(void *obj) {
    cJSON_free(obj);
}

static inline bool JSON_IS_STRING(const JSON_H * const item) {
    return cJSON_IsString(item);
}

static inline bool JSON_IS_NUMBER(const JSON_H * const item) {
    return cJSON_IsNumber(item);
}

static inline bool JSON_IS_OBJECT(const JSON_H * const item) {
    return cJSON_IsObject(item);
}

static inline bool JSON_IS_ARRAY(const JSON_H * const item) {
    return cJSON_IsArray(item);
}

static inline bool JSON_IS_BOOL(const JSON_H * const item) {
    return cJSON_IsBool(item);
}

static inline bool JSON_IS_TRUE(const JSON_H * const item) {
    return cJSON_IsTrue(item);
}

static inline bool JSON_IS_FALSE(const JSON_H * const item) {
    return cJSON_IsFalse(item);
}

static inline void JSON_REPLACE_ITEM_IN_OBJ_CASESENS(JSON_H *obj, const char *string, JSON_H *newitem) {
	cJSON_ReplaceItemInObjectCaseSensitive(obj, string, newitem);
}

#else
typedef void JSON_H;
JSON_H *JSON_CREATE_OBJECT(void);
JSON_H *JSON_GET_OBJECT_ITEM(const JSON_H * const obj, const char * const string);
JSON_H *JSON_GET_CHILD_ITEM(const JSON_H * const obj);
JSON_H *JSON_GET_NEXT_ITEM(const JSON_H * const obj);
char *JSON_GET_OBJECT_ITEM_STRING(const JSON_H * const obj);
double JSON_GET_NUMBER_VALUE(const JSON_H * const item);
JSON_H *JSON_DUPLICATE(const JSON_H* item, bool recurse);
void JSON_ADD_ITEM_TO_OBJECT(JSON_H *obj, const char *string, JSON_H *item);
void JSON_ADD_NUMBER_TO_OBJECT(JSON_H * const obj, const char * const name, const double number);
void JSON_ADD_STRING_TO_OBJECT(JSON_H * const obj, const char * const name, const char * const string);
void JSON_ADD_BOOL_TO_OBJECT(JSON_H * const obj, const char * const name, const bool boolean);
JSON_H *JSON_CREATE_STRING(const char *string);
JSON_H *JSON_CREATE_STRING_ARRAY(const char **strings, int count);
char *JSON_PRINT(const JSON_H *item);
void JSON_DELETE(JSON_H *item);
JSON_H *JSON_CREATE_ARRAY(void);
void JSON_ADD_ITEM_TO_ARRAY(JSON_H *array, JSON_H *item);
int JSON_GET_ARRAY_SIZE(const JSON_H *array);
JSON_H *JSON_GET_ARRAY_ITEM(const JSON_H *array, int index);
JSON_H *JSON_PARSE(const char *value);
char *JSON_GET_STRING_VALUE(JSON_H *item);
JSON_H *JSON_CREATE_NUMBER(double num);
void JSON_FREE(void *obj);
bool JSON_IS_STRING(const JSON_H * const item);
bool JSON_IS_NUMBER(const JSON_H * const item);
bool JSON_IS_OBJECT(const JSON_H * const item);
bool JSON_IS_ARRAY(const JSON_H * const item);
bool JSON_IS_BOOL(const JSON_H * const item);
bool JSON_IS_TRUE(const JSON_H * const item);
bool JSON_IS_FALSE(const JSON_H * const item);
void JSON_REPLACE_ITEM_IN_OBJ_CASESENS(JSON_H *obj, const char *string, JSON_H *newitem);
#endif



#endif //ST_DEVICE_SDK_C_JSON_H
