/* ***************************************************************************
 *
 * Copyright 2019-2020 Samsung Electronics All Rights Reserved.
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
#ifndef _IOT_CAPS_HELPER_
#define _IOT_CAPS_HELPER_

#define _ATTR_BIT_VALUE_MIN 0
#define _ATTR_BIT_VALUE_MAX 1
#define _ATTR_BIT_VALUE_REQUIRED	2
#define _ATTR_BIT_UNIT_REQUIRED	3
#define _ATTR_BIT_MAX_LENGTH	4
#define _ATTR_BIT_VALUE_ARRAY	5

#define ATTR_SET_VALUE_MIN (1 << _ATTR_BIT_VALUE_MIN)
#define ATTR_SET_VALUE_MAX (1 << _ATTR_BIT_VALUE_MAX)
#define ATTR_SET_VALUE_REQUIRED (1 << _ATTR_BIT_VALUE_REQUIRED)
#define ATTR_SET_UNIT_REQUIRED (1 << _ATTR_BIT_UNIT_REQUIRED)
#define ATTR_SET_MAX_LENGTH	(1 << _ATTR_BIT_MAX_LENGTH)
#define ATTR_SET_VALUE_ARRAY	(1 << _ATTR_BIT_VALUE_ARRAY)

#define VALUE_TYPE_INTEGER 1
#define VALUE_TYPE_NUMBER 2
#define VALUE_TYPE_STRING 3
#define VALUE_TYPE_OBJECT 4
#define VALUE_TYPE_BOOLEAN 5

#endif /* _IOT_CAPS_HELPER_ */
