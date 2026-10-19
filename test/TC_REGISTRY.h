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

/*
 * Self-registering test cases for CMocka.
 *
 * A test case written with TEST_F() adds itself to a global registry before
 * main() runs, so it does not have to be declared in TC_FUNCs.h nor listed in
 * the CMUnitTest array of TEST_main.c.
 *
 * Usage inside any TC_FUNC_*.c file:
 *
 *     #include "TC_REGISTRY.h"
 *
 *     TEST_SUITE("iot_api.c");                                 // CMocka group name
 *     TEST_FIXTURE(memleak, my_setup, my_teardown);            // setup/teardown pair
 *
 *     TEST_F(memleak, TC_iot_api_something_pos)
 *     {
 *         UNUSED(state);
 *         assert_int_equal(1, 1);
 *     }
 *
 *     TEST(TC_iot_api_no_fixture_pos)                          // no setup/teardown
 *     {
 *         UNUSED(state);
 *     }
 *
 * Tests run in the order they are defined within a file, and suites run in the
 * order in which their first test registers (i.e. the link order of the object
 * files listed in test/CMakeLists.txt).
 */

#ifndef ST_DEVICE_SDK_C_TC_REGISTRY_H
#define ST_DEVICE_SDK_C_TC_REGISTRY_H

#include "cmocka_custom.h"

typedef void (*TC_test_fn)(void **state);
typedef int (*TC_fixture_fn)(void **state);

/**
 * Append a test case to the registry. Called from the constructors that TEST_F()
 * generates; there is no need to call it directly.
 */
void TC_registry_add(const char *suite_name, const char *test_name, TC_test_fn test_func, TC_fixture_fn setup_func,
                     TC_fixture_fn teardown_func);

/**
 * Run every registered suite as a CMocka group and return the total number of
 * failed test cases. Frees the registry, so it must only be called once.
 */
int TC_registry_run_all(void);

/**
 * Declare the CMocka group name shared by all TEST_F()/TEST() cases of the
 * current file. Exactly one per file, before the first test case.
 */
#define TEST_SUITE(suite_name) static const char *const TC_REGISTRY_SUITE = suite_name

/**
 * Bind a setup/teardown pair to a fixture name usable from TEST_F().
 * Either function may be NULL.
 */
#define TEST_FIXTURE(fixture, setup_func, teardown_func)                                           \
    static TC_fixture_fn const TC_REGISTRY_SETUP_##fixture __attribute__((unused)) = (setup_func); \
    static TC_fixture_fn const TC_REGISTRY_TEARDOWN_##fixture __attribute__((unused)) = (teardown_func)

/**
 * Define a test case and register it under the file's TEST_SUITE() using the
 * setup/teardown of the given TEST_FIXTURE(). The body follows the macro.
 */
#define TEST_F(fixture, test_name)                                                             \
    static void test_name(void **state);                                                       \
    __attribute__((constructor)) static void TC_REGISTRY_REGISTER_##test_name(void)            \
    {                                                                                          \
        TC_registry_add(TC_REGISTRY_SUITE, #test_name, test_name, TC_REGISTRY_SETUP_##fixture, \
                        TC_REGISTRY_TEARDOWN_##fixture);                                       \
    }                                                                                          \
    static void test_name(void **state)

/* Built-in fixture used by TEST(): no setup, no teardown. */
TEST_FIXTURE(TC_REGISTRY_NO_FIXTURE, NULL, NULL);

/**
 * Define a test case that needs no setup/teardown.
 */
#define TEST(test_name) TEST_F(TC_REGISTRY_NO_FIXTURE, test_name)

#endif  // ST_DEVICE_SDK_C_TC_REGISTRY_H
