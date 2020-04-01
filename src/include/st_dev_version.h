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

#ifndef _ST_DEV_VERSION_H_
#define _ST_DEV_VERSION_H_

/* major: api incompatible */
#define VER_MAJOR	(1)

/* minor: feature added. keep api backward compatibility */
#define VER_MINOR	(1)

/* patch: bug fix */
#define VER_PATCH	(7)

/* External Macro for Apps, refer to linux's version.h */
#define STDK_VERSION(a,b,c)	(((a) << 16) + ((b) << 8) + (c))
#define STDK_VERSION_CODE	(STDK_VERSION(VER_MAJOR,VER_MINOR,VER_PATCH))

#endif /* _ST_DEV_VERSION_H_ */
