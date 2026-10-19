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

#include "TC_REGISTRY.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TC_REGISTRY_MAX_SUITES 64
#define TC_REGISTRY_INITIAL_CAPACITY 32

struct tc_registry_suite {
    const char *name;
    struct CMUnitTest *tests;
    size_t count;
    size_t capacity;
};

static struct tc_registry_suite tc_registry_suites[TC_REGISTRY_MAX_SUITES];
static size_t tc_registry_suite_count;

static struct tc_registry_suite *tc_registry_get_suite(const char *suite_name)
{
    size_t i;

    for (i = 0; i < tc_registry_suite_count; i++) {
        if (strcmp(tc_registry_suites[i].name, suite_name) == 0) {
            return &tc_registry_suites[i];
        }
    }

    if (tc_registry_suite_count == TC_REGISTRY_MAX_SUITES) {
        fprintf(stderr, "TC_REGISTRY: more than %d test suites, raise TC_REGISTRY_MAX_SUITES\n",
                TC_REGISTRY_MAX_SUITES);
        abort();
    }

    tc_registry_suites[tc_registry_suite_count].name = suite_name;
    return &tc_registry_suites[tc_registry_suite_count++];
}

void TC_registry_add(const char *suite_name, const char *test_name, TC_test_fn test_func, TC_fixture_fn setup_func,
                     TC_fixture_fn teardown_func)
{
    struct tc_registry_suite *suite = tc_registry_get_suite(suite_name);
    struct CMUnitTest *entry;

    if (suite->count == suite->capacity) {
        size_t capacity = (suite->capacity == 0) ? TC_REGISTRY_INITIAL_CAPACITY : (suite->capacity * 2);
        struct CMUnitTest *grown = realloc(suite->tests, capacity * sizeof(*grown));
        if (grown == NULL) {
            fprintf(stderr, "TC_REGISTRY: out of memory while registering %s\n", test_name);
            abort();
        }
        suite->tests = grown;
        suite->capacity = capacity;
    }

    entry = &suite->tests[suite->count++];
    entry->name = test_name;
    entry->test_func = test_func;
    entry->setup_func = setup_func;
    entry->teardown_func = teardown_func;
    entry->initial_state = NULL;
}

int TC_registry_run_all(void)
{
    int err = 0;
    size_t i;

    for (i = 0; i < tc_registry_suite_count; i++) {
        struct tc_registry_suite *suite = &tc_registry_suites[i];

        err += _cmocka_run_group_tests(suite->name, suite->tests, suite->count, NULL, NULL);

        free(suite->tests);
        suite->tests = NULL;
        suite->count = 0;
        suite->capacity = 0;
    }
    tc_registry_suite_count = 0;

    return err;
}
