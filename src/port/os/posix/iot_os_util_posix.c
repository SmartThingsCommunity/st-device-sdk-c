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

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <pthread.h>
#include <sched.h>
#include <mqueue.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include "iot_debug.h"
#include "iot_error.h"
#include "iot_os_util.h"
#include "iot_bsp_random.h"

const unsigned int iot_os_max_delay = 0xFFFFFFFF;
const unsigned int iot_os_true = true;
const unsigned int iot_os_false = false;

const char* iot_os_get_os_name()
{
       return "POSIX";
}

#define _STR_HELPER(x) #x
#define _STR(x) _STR_HELPER(x)
const char* iot_os_get_os_version_string()
{
#ifdef _POSIX_VERSION
       return _STR(_POSIX_VERSION);
#else
       return "";
#endif
}

/* Thread */
int iot_os_thread_create(void * thread_function, const char* name, int stack_size,
		void* data, int priority, iot_os_thread* thread_handle)
{
	pthread_t* thread = malloc(sizeof(pthread_t));
	pthread_attr_t attr;

	if (thread == NULL)
		return IOT_OS_FALSE;

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	pthread_create(thread, &attr, thread_function, data);

	pthread_attr_destroy(&attr);

	if (thread_handle != NULL) {
		*thread_handle = (iot_os_thread*)thread;
	}

	return IOT_OS_TRUE;
}

void iot_os_thread_delete(iot_os_thread thread_handle)
{
	if (thread_handle != NULL) {
		pthread_t* thread = (pthread_t*)thread_handle;
		pthread_cancel(*thread);
		free(thread);
	} else {
		pthread_cancel(pthread_self());
	}
}

void iot_os_thread_yield()
{
	sched_yield();
}

int iot_os_thread_get_current_handle(iot_os_thread* thread_handle)
{
    if (thread_handle == NULL) {
        return IOT_OS_FALSE;
    }

    *thread_handle = (iot_os_thread)pthread_self();
    return IOT_OS_TRUE;
}

/* Event Group */

#define EVENT_MAX 8

typedef struct {
	unsigned char id;
	int fd[2];
} event_t;

typedef struct {
	event_t group[EVENT_MAX];
	unsigned char event_status;
	pthread_mutex_t mutex;
} eventgroup_t;

iot_os_eventgroup* iot_os_eventgroup_create(void)
{
	eventgroup_t *eventgroup = malloc(sizeof(eventgroup_t));
	if (eventgroup == NULL)
		return NULL;

	if (pthread_mutex_init(&eventgroup->mutex, NULL)) {
		free(eventgroup);
		return NULL;
	}

	for (int i = 0; i < EVENT_MAX; i++) {
		eventgroup->group[i].id = (1 << i);
		int ret = pipe(eventgroup->group[i].fd);
		if (ret == -1) {
			free(eventgroup);
			return NULL;
		}
	}

	eventgroup->event_status = 0;

	return eventgroup;
}

void iot_os_eventgroup_delete(iot_os_eventgroup* eventgroup_handle)
{
	eventgroup_t* eventgroup = eventgroup_handle;

	for (int i = 0; i < EVENT_MAX; i++) {
		close(eventgroup->group[i].fd[0]);
		close(eventgroup->group[i].fd[1]);
	}
	pthread_mutex_destroy(&eventgroup->mutex);
	free(eventgroup);
}

unsigned char iot_os_eventgroup_wait_bits(iot_os_eventgroup* eventgroup_handle,
		const unsigned char bits_to_wait_for, const int clear_on_exit, const unsigned int wait_time_ms)
{
	eventgroup_t *eventgroup = eventgroup_handle;
	fd_set readfds;
	int fd_max = 0;
	unsigned char event_status_backup;

	FD_ZERO(&readfds);

	for (int i = 0; i < EVENT_MAX; i++) {
		if (eventgroup->group[i].id == (eventgroup->group[i].id & bits_to_wait_for)) {
			FD_SET(eventgroup->group[i].fd[0], &readfds);
			if (eventgroup->group[i].fd[0] >= fd_max) {
				fd_max = eventgroup->group[i].fd[0];
			}
		}
	}

	char buf[3] = {0,};
	struct timeval tv;
	memset(&tv, 0x00, sizeof(tv));
	unsigned char bits = 0x00;
	ssize_t read_size = 0;

	tv.tv_sec = wait_time_ms / 1000;
	tv.tv_usec = (wait_time_ms % 1000) * 1000;

	int ret = select(fd_max + 1, &readfds, NULL, NULL, &tv);
	pthread_mutex_lock(&eventgroup->mutex);
	if (ret == -1) {
		// Select Error
		pthread_mutex_unlock(&eventgroup->mutex);
		return 0;
	} else if (ret == 0) {
		// Select Timeout
		pthread_mutex_unlock(&eventgroup->mutex);
		return (unsigned int)eventgroup->event_status;
	} else {
		// read pipe
		for (int i = 0; i < EVENT_MAX; i++) {
			if (eventgroup->group[i].id == (eventgroup->group[i].id & bits_to_wait_for)) {
				if (FD_ISSET(eventgroup->group[i].fd[0], &readfds)) {
					memset(buf, 0, sizeof(buf));
					read_size = read(eventgroup->group[i].fd[0], buf, sizeof(buf));
					IOT_DEBUG("read_size = %d (%d)", read_size, i);
					bits |= eventgroup->group[i].id;
				}
			}
		}

		event_status_backup = eventgroup->event_status;
		if (clear_on_exit) {
			eventgroup->event_status &= ~(bits);
		}
		pthread_mutex_unlock(&eventgroup->mutex);

		return (unsigned int)event_status_backup;
	}
}

int iot_os_eventgroup_set_bits(iot_os_eventgroup* eventgroup_handle,
		const unsigned char bits_to_set)
{
	eventgroup_t *eventgroup = eventgroup_handle;
	unsigned char bits = 0;
	ssize_t write_size = 0;

	pthread_mutex_lock(&eventgroup->mutex);
	for (int i = 0; i < EVENT_MAX; i++) {
        if (eventgroup->group[i].id == (eventgroup->group[i].id & eventgroup->event_status)) {
            IOT_DEBUG("already set 0x%08x (%d)", eventgroup->group[i].id, i);
            continue;
        }
		if (eventgroup->group[i].id == (eventgroup->group[i].id & bits_to_set)) {
			write_size = write(eventgroup->group[i].fd[1], "Set", strlen("Set"));
			IOT_DEBUG("write_size = %d (%d)", write_size, i);
			bits |= eventgroup->group[i].id;
		}
	}

	eventgroup->event_status |= bits;
	pthread_mutex_unlock(&eventgroup->mutex);

	return IOT_OS_TRUE;
}

int iot_os_eventgroup_clear_bits(iot_os_eventgroup* eventgroup_handle,
		const unsigned char bits_to_clear)
{
    eventgroup_t *eventgroup = eventgroup_handle;

	pthread_mutex_lock(&eventgroup->mutex);
    eventgroup->event_status &= ~(bits_to_clear);
    // TODO: clear written event to pipe
	pthread_mutex_unlock(&eventgroup->mutex);

	return IOT_OS_TRUE;
}

/* Mutex */

int iot_os_mutex_init(iot_os_mutex* mutex)
{
	if (!mutex) {
		return IOT_OS_FALSE;
	}

	pthread_mutex_t* mutex_p = malloc(sizeof(pthread_mutex_t));
	if (!mutex_p) {
		return IOT_OS_FALSE;
	} else {
		pthread_mutex_init(mutex_p, NULL);
		mutex->sem = mutex_p;
	}
	return IOT_OS_TRUE;
}

int iot_os_mutex_lock(iot_os_mutex* mutex)
{
	int ret;

	if (!mutex || !mutex->sem) {
		return IOT_OS_FALSE;
	}

	pthread_mutex_t* mutex_p = mutex->sem;

	ret = pthread_mutex_lock(mutex_p);
	if (ret) {
		return IOT_OS_FALSE;
	} else {
		return IOT_OS_TRUE;
	}
}

int iot_os_mutex_unlock(iot_os_mutex* mutex)
{
	int ret;

	if (!mutex || !mutex->sem) {
		return IOT_OS_FALSE;
	}

	pthread_mutex_t* mutex_p = mutex->sem;

	ret = pthread_mutex_unlock(mutex_p);
	if (ret) {
		return IOT_OS_FALSE;
	} else {
		return IOT_OS_TRUE;
	}
}

void iot_os_mutex_destroy(iot_os_mutex* mutex)
{
	if (!mutex || !mutex->sem) {
		return;
	}
	pthread_mutex_t* mutex_p = mutex->sem;

	pthread_mutex_destroy(mutex_p);
	free(mutex_p);
	mutex->sem = NULL;
}

/* Delay */
void iot_os_delay(unsigned int delay_ms)
{
	struct timespec ts = {0,};

	ts.tv_sec = delay_ms / 1000;
	ts.tv_nsec = (delay_ms % 1000) * 1000000;

	nanosleep(&ts, NULL);
}

void iot_os_timer_count_ms(iot_os_timer timer, unsigned int timeout_ms)
{
	timer_t* timer_id = (timer_t*) timer;
	struct itimerspec it;

	it.it_interval.tv_sec = 0;
	it.it_interval.tv_nsec = 0;
	it.it_value.tv_sec = timeout_ms / 1000;
	it.it_value.tv_nsec = (timeout_ms % 1000) * 1000000;

	int ret = timer_settime(*timer_id, 0, &it, NULL);
	if (ret == -1) {
		return;
	}
}

unsigned int iot_os_timer_left_ms(iot_os_timer timer)
{
	timer_t* timer_id = (timer_t*) timer;
	struct itimerspec it = {0,};
	unsigned int left = 0;

	int ret = timer_gettime(*timer_id, &it);
	if (ret == -1) {
		return 0;
	}

	return (it.it_value.tv_sec * 1000) + (it.it_value.tv_nsec / 1000000);
}

char iot_os_timer_isexpired(iot_os_timer timer)
{
	timer_t* timer_id = (timer_t*) timer;
	struct itimerspec it = {0,};

	int ret = timer_gettime(*timer_id, &it);
	if (ret == -1) {
		return IOT_OS_TRUE;
	}

	if (it.it_value.tv_sec == 0 && it.it_value.tv_nsec == 0) {
		return IOT_OS_TRUE;
	} else {
		return IOT_OS_FALSE;
	}
}

int iot_os_timer_init(iot_os_timer *timer)
{
	timer_t* timer_id = malloc(sizeof(timer_t));
	struct sigevent sig;

	if (timer_id == NULL)
		return IOT_ERROR_MEM_ALLOC;

	memset(&sig, '\0', sizeof(struct sigevent));
	sig.sigev_notify = SIGEV_NONE;
	sig.sigev_value.sival_ptr = timer_id;
	int ret = timer_create(CLOCK_REALTIME, &sig, timer_id);
	if (ret == -1) {
		free(timer_id);
		return IOT_ERROR_BAD_REQ;
	}

	*timer = timer_id;

	return IOT_ERROR_NONE;
}

void iot_os_timer_destroy(iot_os_timer *timer)
{
	timer_t* timer_id = (timer_t*) *timer;

	timer_delete(*timer_id);
	free(timer_id);
	timer = NULL;
}

void *iot_os_malloc(size_t size)
{
    return malloc(size);
}

void *iot_os_calloc(size_t nmemb, size_t size)
{
    return calloc(nmemb, size);
}

char *iot_os_realloc(void *ptr, size_t size)
{
    return realloc(ptr, size);
}

void iot_os_free(void *ptr)
{
    return free(ptr);
}

char *iot_os_strdup(const char *src)
{
    return strdup(src);
}

typedef struct _posix_timer_handle {
	timer_t timerId;
	bool is_started;
	iot_os_timer_cb user_cb;
	void *user_data;
	unsigned int expiry_time_ms;
} posix_timer_handle_t;

static void _port_timer_cb(union sigval timer_data)
{
	posix_timer_handle_t *timer_handle = timer_data.sival_ptr;
	timer_handle->is_started = false;

	if (timer_handle->user_cb) {
		timer_handle->user_cb((iot_os_timer_handle)timer_handle, timer_handle->user_data);
	}
}

iot_os_timer_handle iot_os_timer_create(iot_os_timer_cb cb, unsigned int expiry_time_ms, void *user_data)
{
	posix_timer_handle_t *new_timer_handle;
	int res;
	struct sigevent sev = { 0 };

	new_timer_handle = (posix_timer_handle_t *)malloc(sizeof(posix_timer_handle_t));
	if (new_timer_handle == NULL) {
		return NULL;
	}
	memset(new_timer_handle, 0, sizeof(posix_timer_handle_t));

    sev.sigev_notify = SIGEV_THREAD;
    sev.sigev_notify_function = &_port_timer_cb;
    sev.sigev_value.sival_ptr = new_timer_handle;
	res = timer_create(CLOCK_MONOTONIC, &sev, &new_timer_handle->timerId);
	if (res != 0) {
		free(new_timer_handle);
		return NULL;
	}

	new_timer_handle->user_cb = cb;
	new_timer_handle->user_data = user_data;
	new_timer_handle->is_started = false;
	new_timer_handle->expiry_time_ms = expiry_time_ms;

	return (iot_os_timer_handle)new_timer_handle;
}

void iot_os_timer_delete(iot_os_timer_handle timer_handle)
{
	int err;
	posix_timer_handle_t *port_timer_handle = (posix_timer_handle_t *)timer_handle;

	err = timer_delete(port_timer_handle->timerId);
	if (err != 0) {
		printf("Failed to delete timer\n");
	}
	free(port_timer_handle);
}

int iot_os_timer_start(iot_os_timer_handle timer_handle)
{
	posix_timer_handle_t *port_timer_handle = (posix_timer_handle_t *)timer_handle;
    struct itimerspec its = { 0,};
	int err;

	its.it_value.tv_sec = port_timer_handle->expiry_time_ms / 1000;
	its.it_value.tv_nsec = (port_timer_handle->expiry_time_ms % 1000) * 1000;

	err = timer_settime(port_timer_handle->timerId, 0, &its, NULL);
	if (err != 0) {
		printf("Failed to start timer\n");
	} else {
		port_timer_handle->is_started = true;
	}
	return err;
}

int iot_os_timer_stop(iot_os_timer_handle timer_handle)
{
	posix_timer_handle_t *port_timer_handle = (posix_timer_handle_t *)timer_handle;
    struct itimerspec its = { 0,};
	int err;

	err = timer_settime(port_timer_handle->timerId, 0, &its, NULL);
	if (err != 0) {
		printf("Failed to stop timer\n");
	} else {
		port_timer_handle->is_started = false;
	}
	return err;
}

bool iot_os_timer_is_active(iot_os_timer_handle timer_handle)
{
	posix_timer_handle_t *port_timer_handle = (posix_timer_handle_t *)timer_handle;
	return port_timer_handle->is_started;
}
