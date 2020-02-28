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
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include "TCs.h"

int main(void) {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test(TC_iot_util_get_random_uuid),
            cmocka_unit_test(TC_iot_util_convert_str_mac),
            cmocka_unit_test(TC_iot_api_device_info_load),
            cmocka_unit_test(TC_iot_api_onboarding_config_load),
            cmocka_unit_test(TC_iot_uuid_from_mac),
            cmocka_unit_test(TC_iot_random_uuid_from_mac),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}