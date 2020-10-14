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

#ifndef _IOT_OS_UTIL_H_
#define _IOT_OS_UTIL_H_
#include <stdlib.h>

typedef void *iot_os_thread;
typedef void iot_os_queue;
typedef void iot_os_eventgroup;
typedef void iot_os_sem;
typedef void *iot_os_timer;

/**
 * @brief Contains a mutex data.
 */
typedef struct iot_os_mutex
{
	iot_os_sem* sem;	/**< @brief semaphore */
} iot_os_mutex;

#define IOT_DELAY(x) iot_os_delay(x)

#define IOT_OS_MAX_DELAY iot_os_max_delay
#define IOT_OS_TRUE iot_os_true
#define IOT_OS_FALSE iot_os_false

extern const unsigned int iot_os_max_delay;
extern const unsigned int iot_os_true;
extern const unsigned int iot_os_false;


/*
 * @brief get os name
 * @return
 *  return is string of os name
 */
const char* iot_os_get_os_name();

/*
 * @brief get os version string
 * @return
 *  return is string of os version
 */
const char* iot_os_get_os_version_string();

/**
 * @brief	create and run thread
 *
 * This function creates and runs thread
 *
 * @param[in] thread_function	function pointer for thread loop
 * @param[in] name	name of thread
 * @param[in] stack_size	stack size of thread
 * @param[in] data	data that will passed into the thread as the parameter
 * @param[in] priority	priority of thread created by this function
 * @param[out] thread_handle	thread handle of thread created by this function
 *	(optional, NULL is possible)
 *
 * @return
 *	IOT_OS_TRUE : success
 *	otherwise :  fail
 */
int iot_os_thread_create(void * thread_function, const char* name, int stack_size,
	void* data, int priority, iot_os_thread* thread_handle);

/**
 * @brief	delete thread
 *
 * This function delete thread
 *
 * @param[in] thread_handle	thread handle of thread to delete(if NULL is passed, delete current thread)
 *
 */
void iot_os_thread_delete(iot_os_thread thread_handle);

/**
 * @brief	yield task
 *
 * This function yields task
 *
 */
void iot_os_thread_yield();

/**
 * @brief	get curruent thread handle
 *
 * This function will return current thread handle
 *
 * @param[out] thread_handle	thread handle of current thread
 *
 * @return
 *	IOT_OS_TRUE : success
 *	otherwise :  fail
 */
int iot_os_thread_get_current_handle(iot_os_thread* thread_handle);

/**
 * @brief	create queue
 *
 * This function create queue and return queue handle
 *
 * @param[in] queue_length	maximum number of queue item
 * @param[in] item_size	size of item
 *
 * @return
 *	return is queue handle of queue created by this function
 *	If queue was not created, NULL is returned.
 *
 */
iot_os_queue* iot_os_queue_create(int queue_length, int item_size);

/**
 * @brief	reset queue
 *
 * This function reset queue
 *
 * @param[in] queue_handle	handle of queue to reset.
 *
 * @return
 *	IOT_OS_TRUE : success
 *  otherwise : fail
 *
 */
int iot_os_queue_reset(iot_os_queue* queue_handle);

/**
 * @brief	delete queue
 *
 * This function delete queue
 *
 * @param[in] queue_handle	handle of queue to be deleted.
 *
 */
void iot_os_queue_delete(iot_os_queue* queue_handle);

/**
 * @brief	send message to the back of queue.
 *
 * This function will send item to the back of queue
 *
 * @param[in] queue_handle	handle of queue to save item
 * @param[in] data	item to be saved in queue
 * @param[in] wait_time_ms	maximum time to wait until queue is available
 *
 * @return
 *	IOT_OS_TRUE : success
 *	otherwise :  fail
 *
 */
int iot_os_queue_send(iot_os_queue* queue_handle, void * data, unsigned int wait_time_ms);

/**
 * @brief	receive message from the front of queue.
 *
 * This function will receive item from the front of queue
 *
 * @param[in] queue_handle	handle of queue to receive item
 * @param[in] data	buffer for item received from queue
 * @param[in] wait_time_ms	maximum time to wait until queue is not empty
 *
 * @return
 *	IOT_OS_TRUE : success
 *	otherwise :  fail
 *
 */
int iot_os_queue_receive(iot_os_queue* queue_handle, void * data, unsigned int wait_time_ms);

/**
 * @brief	create eventgroup
 *
 * This function create eventgroup and return eventgroup handle
 *
 *
 * @return
 *	return is eventgroup handle of eventgroup created by this function
 *	If eventgroup was not created, NULL is returned.
 *
 */
iot_os_eventgroup* iot_os_eventgroup_create(void);

/**
 * @brief	delete eventgroup
 *
 * This function delete eventgroup
 *
 * @param[in] eventgroup_handle	eventgroup handle of eventgroup to delete
 *
 */
void iot_os_eventgroup_delete(iot_os_eventgroup* eventgroup_handle);

/**
 * @brief	wait for bit of group of bits to become set
 *
 * This function will wait for event bit
 *
 * @param[in] eventgroup_handle	handle of eventgroup waiting for
 * @param[in] bits_to_wait_for	bitwise value of bit/bits.
 *	ex) use 0b101 to wait bit 0 and/or bit 2
 * @param[in] clear_on_exit	if this value is IOT_OS_TRUE,
 *	bits in 'bits_to_wait_for' will be cleared
 * @param[in] wait_time_ms	maximum time to wait until all/one of bits are set
 *
 * @return
 *	return is bits of eventgroup.
 *  if you wait for bit0 and bit3, can check with  was setted, return will be 0b101 = 5
 *
 */
unsigned char iot_os_eventgroup_wait_bits(iot_os_eventgroup* eventgroup_handle,
	const unsigned char bits_to_wait_for, const int clear_on_exit, const unsigned int wait_time_ms);
/**
 * @brief	set bit/bits of eventgroup
 *
 * This function will set bit/bits of eventgroup
 *
 * @param[in] eventgroup_handle	handle of eventgroup to set bit/bits
 * @param[in] bits_to_set	bitwise value of bit/bits to set
 *	ex) use 0b101 will set bit0 and bit2
 *	ex) use 0b100 will set only bit2
 *
 * @return
 *	return IOT_OS_TRUE on success, IOT_OS_FALSE on failure
 *
 */
int iot_os_eventgroup_set_bits(iot_os_eventgroup* eventgroup_handle,
	const unsigned char bits_to_set);
/**
 * @brief	clear bit/bits of eventgroup
 *
 * This function will clear bit/bits of eventgroup
 *
 * @param[in] eventgroup_handle	handle of eventgroup to cleat bit/bits
 * @param[in] bits_to_clear	bitwise value of bit/bits to clear
 *	ex) use 0b101 will clear bit0 and bit2
 *	ex) use 0b100 will clear only bit2
 *
 * @return
 *	return IOT_OS_TRUE on success, IOT_OS_FALSE on failure
 *
 */
int iot_os_eventgroup_clear_bits(iot_os_eventgroup* eventgroup_handle,
	const unsigned char bits_to_clear);


/**
 * @brief	create mutex
 *
 * This function will create mutex
 *
 * @param[out] mutex	handle of mutex created by this function
 *
 * @return
 *	IOT_OS_TRUE : success
 *	otherwise : fail
 */
int iot_os_mutex_init(iot_os_mutex* mutex);

/**
 * @brief	mutex lock
 *
 * This function will lock mutex before critical section
 *
 * @param[in] mutex	handle of mutex
 *
 * @return
 *	IOT_OS_TRUE : success
 *	otherwise : fail
 */
int iot_os_mutex_lock(iot_os_mutex* mutex);

/**
 * @brief	mutex unlock
 *
 * This function will unlock mutex after critical section
 *
 * @param[in] mutex	handle of mutex
 *
 * @return
 *	IOT_OS_TRUE : success
 *	otherwise : fail
 */
int iot_os_mutex_unlock(iot_os_mutex* mutex);

/**
 * @brief	destroy mutex
 *
 * This function will destroy a mutex
 *
 * @param[in] mutex	handle of mutex.
 */
void iot_os_mutex_destroy(iot_os_mutex* mutex);

/**
 * @brief	delay a thread
 *
 * This function will delay thread for given time
 *
 * @param[in] delay	time to wait
 *
 */
void iot_os_delay(unsigned int delay_ms);

/**
 * @brief	init timer
 *
 * This function will init timer struct
 *
 * @param[in] timer	pointer of timer to init
 *
 * @return
 *	IOT_ERROR_NONE : success
 *	otherwise : fail
 */
int iot_os_timer_init(iot_os_timer* timer);

/**
 * @brief	check timer expired
 *
 * This function will check if timer is expired
 *
 * @param[in] timer	timer handle
 *
 * @return
 *	1 : timer is expired
 *	0 : timer is not expired
 */
char iot_os_timer_isexpired(iot_os_timer timer);

/**
 * @brief	set timer count
 *
 * This function will set timer count in ms unit.
 *
 * @param[in] timer	timer handle
 * @param[in] count	count to set in ms unit
 *
 */
void iot_os_timer_count_ms(iot_os_timer timer, unsigned int timeout_ms);

/**
 * @brief	return remaining time in ms unit
 *
 * This function will return remaining time in ms unit
 *
 * @param[in] timer	timer handle
 *
 * @return
 * 	0 : timer is expired
 *	non-zero : remaining time
 */
unsigned int iot_os_timer_left_ms(iot_os_timer timer);

/**
 * @brief	destroy timer
 *
 * This function will destroy timer struct
 *
 * @param[in] timer	pointer of timer to destroy
 *
 */
void iot_os_timer_destroy(iot_os_timer* timer);

#if defined(CONFIG_STDK_IOT_CORE_OS_SUPPORT_POSIX)
/**
 * @brief	allocate memory
 *
 * This function will allocate size bytes and returns a pointer to the allocated memory
 *
 * @param[in] size bytes of memory to allocate
 *
 */
void *iot_os_malloc(size_t size);

/**
 * @brief	allocate memory
 *
 * This function allocates memory for an array of nmemb elements of size bytes each
 * and returns a pointer to the allocated memory.
 *
 * @param[in] nmemb count of memory block to allocate
 * @param[in] size bytes of memory block to allocate
 *
 */
void *iot_os_calloc(size_t nmemb, size_t size);

/**
 * @brief	change allocated memory size
 *
 * This function changes the size of the memory block pointed to by ptr to size bytes.
 * If the new size is larger than the old size, the added memory will not be initialized.
 *
 * @param[in] ptr a pointer of memory to change
 * @param[in] size a bytes of memory to change
 *
 */
char *iot_os_realloc(void *ptr, size_t size);

/**
 * @brief	free memory
 *
 * frees the memory space pointed to by ptr,
 * which must have been returned by a previous call to iot_os_malloc
 *
 * @param[in] ptr pinter of memory
 *
 */
void iot_os_free(void *ptr);

/**
 * @brief	duplicate a string
 *
 * this function returns a pointer to a new string which is a duplicate of the string src.
 * Memory for the new string is obtained with iot_os_malloc, and can be freed with iot_os_free
 *
 * @param[in] src string to duplicate
 *
 */
char *iot_os_strdup(const char *src);
#else
#include <string.h>
static inline void *iot_os_malloc(size_t size) { return malloc(size); }
static inline void *iot_os_calloc(size_t nmemb, size_t size) { return calloc(nmemb, size); }
static inline void *iot_os_realloc(void *ptr, size_t size) { return realloc(ptr, size); }
static inline void iot_os_free(void *ptr) { return free(ptr); }
static inline char *iot_os_strdup(const char *src) { return strdup(src); }
#endif

#endif /* _IOT_OS_UTIL_H_ */
