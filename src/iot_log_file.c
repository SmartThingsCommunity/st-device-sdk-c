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

#if defined(CONFIG_STDK_IOT_CORE_LOG_FILE)
#include <stdio.h>
#include <sys/time.h>
#include "iot_os_util.h"
#include "iot_log_file.h"

struct iot_log_file_ctx *log_ctx;

#ifdef CONFIG_STDK_IOT_CORE_LOG_FILE_FLASH_WITH_RAM
static unsigned int _iot_log_file_buf_free_size(void)
{
	unsigned int free_size = 0;

	if (log_ctx != NULL) {
		free_size = IOT_LOG_FILE_RAM_BUF_SIZE - log_ctx->log_buf.cnt;
	} else {
		IOT_LOG_FILE_ERROR("log_ctx is NULL! %s %d\n", __FUNCTION__, __LINE__);
		return 0;
	}

	return free_size;
}
#endif

static void _iot_log_file_store_char(char character)
{
	unsigned int cnt;

	if (log_ctx != NULL) {
		cnt = log_ctx->log_buf.cnt;
	} else {
		IOT_LOG_FILE_ERROR("log_ctx is NULL! %s %d\n", __FUNCTION__, __LINE__);
		return;
	}

	if (cnt >= IOT_LOG_FILE_RAM_BUF_SIZE) {
		log_ctx->log_buf.cnt = 0;
		log_ctx->log_buf.overridden = IOT_LOG_FILE_TRUE;

		cnt = 0;
	}

	log_ctx->log_buf.buf[cnt] = character;

	log_ctx->log_buf.cnt++;
}

static void _iot_log_file_enable(unsigned int enable)
{
	IOT_LOG_FILE_DEBUG("[%s] %d\n", __FUNCTION__, enable);

	if (log_ctx != NULL) {
		log_ctx->log_buf.enable = enable;
	} else {
		IOT_LOG_FILE_ERROR("log_ctx is NULL! %s %d\n", __FUNCTION__, __LINE__);
		return;
	}
}

static void _iot_log_file_open_state(bool open_state)
{
	if (log_ctx != NULL) {
		log_ctx->file_opened = open_state;
	}
}

static bool _iot_log_file_is_opening(void)
{
	bool ret = IOT_LOG_FILE_FALSE;

	if (log_ctx != NULL) {
		ret = log_ctx->file_opened;
	}

	return ret;
}

int iot_log_file_store(const char *log_data, size_t log_size)
{
	unsigned int iot_log_file_cnt = 0;
#ifdef CONFIG_STDK_IOT_CORE_LOG_FILE_FLASH_WITH_RAM
	unsigned int iot_log_file_free_size = 0;
#endif

	if (log_ctx == NULL) {
		//IOT_LOG_FILE_ERROR("iot log is not initialized\n");
		return -1;
	}

	if (log_ctx->log_buf.enable == IOT_LOG_FILE_FALSE) {
		//IOT_LOG_FILE_ERROR("iot log buf is disabled\n");
		return -1;
	}

	if (log_size >= IOT_LOG_FILE_MAX_STRING_SIZE) {
		return -1;
	}

	while (iot_log_file_cnt < log_size)	{
		_iot_log_file_store_char(*(log_data++));
		iot_log_file_cnt++;
	}

#ifdef CONFIG_STDK_IOT_CORE_LOG_FILE_FLASH_WITH_RAM
	iot_log_file_free_size = _iot_log_file_buf_free_size();

	if (iot_log_file_free_size < (IOT_LOG_FILE_MAX_STRING_SIZE * IOT_LOG_FILE_MARGIN_CNT)) {
		if (log_ctx != NULL && log_ctx->events != NULL) {
			_iot_log_file_enable(IOT_LOG_FILE_FALSE);
			iot_os_eventgroup_set_bits(log_ctx->events, IOT_LOG_FILE_EVENT_SYNC_REQ_BIT);
		}
	}
#endif
	return iot_log_file_cnt;
}

void iot_log_file_sync(void)
{
	if (log_ctx->events != NULL) {
		_iot_log_file_enable(IOT_LOG_FILE_FALSE);
		iot_os_eventgroup_set_bits(log_ctx->events, IOT_LOG_FILE_EVENT_SYNC_REQ_BIT);
	}
}

#if 0
static void _iot_log_file_print_hexdump(void *addr, unsigned int size)
{
	int i = 0, j = 0;
	char *data = addr;
	for (i = 0; i < size; i += 128) {
		printf("[%4X]:  ", i);
		for (j = 0; j < 128; j++) {
			printf("%c", data[j + i]);
		}
		printf("\n");
	}
	printf("\n\n\n");
}
#endif

#ifdef CONFIG_STDK_IOT_CORE_LOG_FILE_FLASH_WITH_RAM
static void _iot_log_file_init_header(struct iot_log_file_header_tag *log_file_header)
{
	strcpy(log_file_header->magic_code, "LOG");
	log_file_header->file_size = IOT_LOG_FILE_FLASH_SIZE;
	log_file_header->written_size = 0;
	log_file_header->sector.num = (IOT_LOG_FILE_FLASH_ADDR + IOT_LOG_FILE_FLASH_HEADER_SIZE) / IOT_LOG_FILE_FLASH_SECTOR_SIZE;
	log_file_header->sector.offset = IOT_LOG_FILE_FLASH_HEADER_SIZE;
}

static unsigned int _iot_log_file_sector_to_addr(unsigned int sector_num, unsigned int offset)
{
	unsigned int addr;

	addr = (sector_num * IOT_LOG_FILE_FLASH_SECTOR_SIZE) + offset;

	return addr;
}

static iot_log_file_header_state_t _iot_log_file_load_header(struct iot_log_file_header_tag *log_file_header)
{
	iot_log_file_header_state_t log_header_state = NORMAL;
	iot_error_t iot_err = IOT_ERROR_NONE;

	iot_err = iot_log_read_flash(IOT_LOG_FILE_FLASH_ADDR, log_file_header, IOT_LOG_FILE_FLASH_HEADER_SIZE);
	if (iot_err != IOT_ERROR_NONE) {
		IOT_LOG_FILE_ERROR("%s %d err=%d", __FUNCTION__, __LINE__, iot_err);
		return LOAD_FAIL;
	}

	if ((log_file_header->magic_code[0] == 'L') && (log_file_header->magic_code[1] == 'O') && (log_file_header->magic_code[2] == 'G')) {
		IOT_LOG_FILE_DEBUG("MAGIC OK\n");
		if (log_file_header->file_size != IOT_LOG_FILE_FLASH_SIZE) {
			IOT_LOG_FILE_DEBUG("Log size was updated %d->%d\n", log_file_header->file_size, IOT_LOG_FILE_FLASH_SIZE);
			log_file_header->file_size = IOT_LOG_FILE_FLASH_SIZE;
		}
	} else {
		IOT_LOG_FILE_DEBUG("There is not a log file\n");
		_iot_log_file_init_header(log_file_header);
		log_header_state = NO_MAGIC;
	}

	IOT_LOG_FILE_DEBUG("file_size = %d\n", log_file_header->file_size);
	IOT_LOG_FILE_DEBUG("sector.num = %d\n", log_file_header->sector.num);
	IOT_LOG_FILE_DEBUG("sector.offset = 0x%x\n", log_file_header->sector.offset);

	return log_header_state;
}
#endif
static void _iot_log_file_clear_buf()
{
	if (log_ctx != NULL) {
		log_ctx->log_buf.cnt = 0;
		log_ctx->log_buf.overridden = IOT_LOG_FILE_FALSE;

	} else {
		IOT_LOG_FILE_ERROR("log_ctx is NULL! %s %d\n", __FUNCTION__, __LINE__);
		return;
	}

	if (_iot_log_file_is_opening() == IOT_LOG_FILE_FALSE) {
		_iot_log_file_enable(IOT_LOG_FILE_TRUE);
	}
}

#ifdef CONFIG_STDK_IOT_CORE_LOG_FILE_FLASH_WITH_RAM
static unsigned int _iot_log_file_get_next_sector(unsigned int current_num)
{
	unsigned int next_num;

	next_num = current_num + 1;
	if (next_num >= ((IOT_LOG_FILE_FLASH_ADDR + IOT_LOG_FILE_FLASH_SIZE) / IOT_LOG_FILE_FLASH_SECTOR_SIZE)) {
		next_num = IOT_LOG_FILE_FLASH_FIRST_SECTOR;
	}
	IOT_LOG_FILE_DEBUG("next_num=%d\n", next_num);

	return next_num;
}

static void _iot_log_file_addr_to_sector(struct iot_log_file_sector_tag *sector, unsigned int addr)
{
	sector->num = addr / IOT_LOG_FILE_FLASH_SECTOR_SIZE;
	sector->offset = addr % IOT_LOG_FILE_FLASH_SECTOR_SIZE;
}

static iot_error_t _iot_log_file_write_sector(unsigned int sector_num, unsigned int offset, void *data_addr, unsigned int size)
{
	iot_error_t iot_err = IOT_ERROR_NONE;

	unsigned int sector_addr;
	char *iot_sector_buf;

	IOT_LOG_FILE_DEBUG("%s sector_num=%d  offset=%d data_addr=0x%p size=%d\n", __FUNCTION__, sector_num, offset, data_addr, size);

	iot_sector_buf = iot_os_malloc(IOT_LOG_FILE_FLASH_SECTOR_SIZE);
	if (iot_sector_buf == NULL) {
		IOT_LOG_FILE_ERROR("%s %d malloc fail!\n", __FUNCTION__, __LINE__);
		iot_err = IOT_ERROR_MEM_ALLOC;
		goto end;
	}

	sector_addr = _iot_log_file_sector_to_addr(sector_num, 0);
	IOT_LOG_FILE_DEBUG("sector_addr = 0x%x\n", sector_addr);

	iot_err = iot_log_read_flash(sector_addr, iot_sector_buf, IOT_LOG_FILE_FLASH_SECTOR_SIZE);
	if (iot_err != IOT_ERROR_NONE) {
		IOT_LOG_FILE_ERROR("%s %d err=%d", __FUNCTION__, __LINE__, iot_err);
		goto end;
	}

	iot_err = iot_log_erase_sector(sector_num);
	if (iot_err != IOT_ERROR_NONE) {
		IOT_LOG_FILE_ERROR("%s %d err=%d", __FUNCTION__, __LINE__, iot_err);
		goto end;
	}

	memcpy(iot_sector_buf + offset, data_addr, size);
	iot_err = iot_log_write_flash(sector_addr, iot_sector_buf, IOT_LOG_FILE_FLASH_SECTOR_SIZE);
	if (iot_err != IOT_ERROR_NONE) {
		IOT_LOG_FILE_ERROR("%s %d err=%d", __FUNCTION__, __LINE__, iot_err);
		goto end;
	}

end:
	if (iot_sector_buf != NULL) {
		free(iot_sector_buf);
	}

	return iot_err;
}

static iot_error_t _iot_log_file_write_header(void *buf, struct iot_log_file_header_tag log_file_header)
{
	iot_error_t iot_err = IOT_ERROR_NONE;
	struct iot_log_file_header_tag *plog_file_header;

	iot_err = iot_log_read_flash(IOT_LOG_FILE_FLASH_ADDR, buf, IOT_LOG_FILE_FLASH_SECTOR_SIZE);
	if (iot_err != IOT_ERROR_NONE) {
		IOT_LOG_FILE_ERROR("%s %d err=%d", __FUNCTION__, __LINE__, iot_err);
		goto end;
	}

	plog_file_header = (struct iot_log_file_header_tag *)buf;

	*plog_file_header = log_file_header;

	iot_err = iot_log_erase_sector(IOT_LOG_FILE_FLASH_FIRST_SECTOR);
	if (iot_err != IOT_ERROR_NONE) {
		IOT_LOG_FILE_ERROR("%s %d err=%d", __FUNCTION__, __LINE__, iot_err);
		goto end;
	}

	iot_err = iot_log_write_flash(IOT_LOG_FILE_FLASH_ADDR, buf, IOT_LOG_FILE_FLASH_SECTOR_SIZE);
	if (iot_err != IOT_ERROR_NONE) {
		IOT_LOG_FILE_ERROR("%s %d err=%d", __FUNCTION__, __LINE__, iot_err);
		goto end;
	}

end:
	return iot_err;
}

static iot_error_t _iot_log_file_write_data(unsigned int sector_start_num, char *file_buf, unsigned int file_write_size)
{
	iot_error_t iot_err = IOT_ERROR_NONE;
	unsigned int addr = 0;
	unsigned int remain_write_size = 0;
	unsigned int sector_next = 0;

	addr = _iot_log_file_sector_to_addr(sector_start_num, 0);
	IOT_LOG_FILE_DEBUG("%s addr=0x%X size=0x%X\n", __FUNCTION__, addr, file_write_size);

	/* if size to write is over sector size, we write only sector size to prevent over write */
	if (file_write_size <= IOT_LOG_FILE_FLASH_SECTOR_SIZE) {
		iot_err = _iot_log_file_write_sector(sector_start_num, 0, file_buf, IOT_LOG_FILE_FLASH_SECTOR_SIZE);
		if (iot_err != IOT_ERROR_NONE) {
			IOT_LOG_FILE_ERROR("%s %d err=%d", __FUNCTION__, __LINE__, iot_err);
			goto end;
		}
	} else {
		/********************** first write **************************/
		remain_write_size = file_write_size;
		iot_err = _iot_log_file_write_sector(sector_start_num, 0, file_buf, IOT_LOG_FILE_FLASH_SECTOR_SIZE);
		if (iot_err != IOT_ERROR_NONE) {
			IOT_LOG_FILE_ERROR("%s %d err=%d", __FUNCTION__, __LINE__, iot_err);
			goto end;
		}

		/********************** 2nd write **************************/
		remain_write_size -= IOT_LOG_FILE_FLASH_SECTOR_SIZE;

		sector_next = _iot_log_file_get_next_sector(sector_start_num);

		addr = _iot_log_file_sector_to_addr(sector_next, 0);
		IOT_LOG_FILE_DEBUG("next sector addr = 0x%x\n", addr);

		if (addr != IOT_LOG_FILE_FLASH_ADDR) {
			iot_err = _iot_log_file_write_sector(sector_next, 0, file_buf + IOT_LOG_FILE_FLASH_SECTOR_SIZE, remain_write_size);
			if (iot_err != IOT_ERROR_NONE) {
				IOT_LOG_FILE_ERROR("%s %d err=%d", __FUNCTION__, __LINE__, iot_err);
				goto end;
			}
		} else {
			/* first sector that have a descriptor */
			iot_err = _iot_log_file_write_sector(sector_next, sizeof(struct iot_log_file_header_tag), file_buf + IOT_LOG_FILE_FLASH_SECTOR_SIZE, remain_write_size);
			if (iot_err != IOT_ERROR_NONE) {
				IOT_LOG_FILE_ERROR("%s %d err=%d", __FUNCTION__, __LINE__, iot_err);
				goto end;
			}
		}
	}

	IOT_LOG_FILE_DEBUG("%s writing data was completed\n", __FUNCTION__);

end:
	return iot_err;
}

static iot_error_t _iot_log_file_load_old_data(void *buf, unsigned int *file_write_size, struct iot_log_file_header_tag log_file_header, iot_log_file_header_state_t log_header_state)
{
	iot_error_t iot_err = IOT_ERROR_NONE;
	unsigned int sector_addr = 0;

	if (log_header_state == NORMAL) {
		sector_addr = log_file_header.sector.num * IOT_LOG_FILE_FLASH_SECTOR_SIZE;
		iot_err = iot_log_read_flash(sector_addr, buf, IOT_LOG_FILE_FLASH_SECTOR_SIZE); /* read log from flash */
		if (iot_err != IOT_ERROR_NONE) {
			IOT_LOG_FILE_ERROR("%s %d err=%d", __FUNCTION__, __LINE__, iot_err);
			goto end;
		}
		*file_write_size += log_file_header.sector.offset;
	} else if (log_header_state == NO_MAGIC) {
		memcpy(buf, &log_file_header, sizeof(log_file_header));
		*file_write_size += sizeof(struct iot_log_file_header_tag);
	}

	IOT_LOG_FILE_DEBUG("first file_write_size=0x%X\n", *file_write_size);

end:
	return iot_err;
}

static void _iot_log_file_copy_buf(void *iot_file_buf, void *iot_log_buf, unsigned int offset, unsigned int *file_write_size, unsigned int size)
{
	memcpy(iot_file_buf + offset, iot_log_buf, size);
	*file_write_size += size;

	IOT_LOG_FILE_DEBUG("%s iot_file_buf=0x%p *file_write_size=0x%X\n", __FUNCTION__, iot_file_buf, *file_write_size);
}

static iot_error_t _iot_log_file_update_header(void *buf, struct iot_log_file_header_tag *log_file_header, unsigned int log_buf_size)
{
	iot_error_t iot_err = IOT_ERROR_NONE;

	unsigned int log_max_size = 0;
	unsigned int addr = 0;
	struct iot_log_file_sector_tag sector = {0, 0};

	IOT_LOG_FILE_DEBUG("%s buf=0x%p log_file_header=0x%p log_buf_size=%d\n", __FUNCTION__, buf, log_file_header, log_buf_size);

	if (buf == NULL) {
		iot_err = IOT_ERROR_INVALID_ARGS;
		goto end;
	}

	addr = _iot_log_file_sector_to_addr(log_file_header->sector.num, log_file_header->sector.offset);
	addr = addr + log_buf_size;
	if (addr >= IOT_LOG_FILE_FLASH_MAX_ADDR) {
		addr = addr + sizeof(struct iot_log_file_header_tag);
		_iot_log_file_addr_to_sector(&sector, addr);
		sector.num = IOT_LOG_FILE_FLASH_FIRST_SECTOR;
		log_file_header->sector = sector;
	} else {
		_iot_log_file_addr_to_sector(&(log_file_header->sector), addr);
	}

	log_max_size = (IOT_LOG_FILE_FLASH_SIZE - sizeof(struct iot_log_file_header_tag));
	if ((log_file_header->written_size + log_buf_size) <= log_max_size) {
		log_file_header->written_size += log_buf_size;
	} else {
		log_file_header->written_size = log_max_size;
	}

	IOT_LOG_FILE_DEBUG("log_file_header.sector=%d log_file_header.sector.offset=0x%X written_size=%d\n", log_file_header->sector.num, log_file_header->sector.offset, log_file_header->written_size);

	iot_err = _iot_log_file_write_header(buf, *log_file_header);
	if (iot_err != IOT_ERROR_NONE) {
		IOT_LOG_FILE_ERROR("%s %d err=%d", __FUNCTION__, __LINE__, iot_err);
		goto end;
	}

end:
	return iot_err;
}

static iot_error_t _iot_log_file_manager(struct iot_log_file_ctx *ctx)
{
	unsigned int file_write_size = 0;
	iot_log_file_header_state_t log_header_state = NORMAL;
	iot_error_t iot_err = IOT_ERROR_NONE;

	unsigned int log_buf_size; /* buf size to write */

	log_buf_size = ctx->log_buf.cnt;
	IOT_LOG_FILE_DEBUG("log_buf_size=0x%X\n", log_buf_size);

	/* STEP 1: Load log header */
	log_header_state = _iot_log_file_load_header(&(ctx->file_header));
	if (log_header_state == LOAD_FAIL) {
		IOT_LOG_FILE_ERROR("%s %d err=%d", __FUNCTION__, __LINE__, log_header_state);
		return LOAD_FAIL;
	}

	/* STEP 2: load load data */
	iot_err = _iot_log_file_load_old_data(ctx->file_buf, &file_write_size, ctx->file_header, log_header_state);
	if (iot_err != IOT_ERROR_NONE) {
		IOT_LOG_FILE_ERROR("%s %d err=%d", __FUNCTION__, __LINE__, iot_err);
		goto end;
	}

	/* STEP 3: Copy log data to file buf */
	_iot_log_file_copy_buf(ctx->file_buf, ctx->log_buf.buf, ctx->file_header.sector.offset, &file_write_size, log_buf_size);

	/* STEP 4:  write log data to flash */
	iot_err = _iot_log_file_write_data(ctx->file_header.sector.num, ctx->file_buf, file_write_size);
	if (iot_err != IOT_ERROR_NONE) {
		IOT_LOG_FILE_ERROR("%s %d err=%d", __FUNCTION__, __LINE__, iot_err);
		goto end;
	}

	/* STEP 5:  update header */
	iot_err = _iot_log_file_update_header(ctx->file_buf, &(ctx->file_header), log_buf_size);
	if (iot_err != IOT_ERROR_NONE) {
		IOT_LOG_FILE_ERROR("%s %d err=%d", __FUNCTION__, __LINE__, iot_err);
		goto end;
	}

	/* STEP 6: CLEAR LOG BUF */
	_iot_log_file_clear_buf();

end:
	return iot_err;
}

static void _iot_log_file_task(void *arg)
{
	unsigned int curr_events;
	iot_error_t iot_err;

	_iot_log_file_enable(IOT_LOG_FILE_TRUE);
	while (1) {
		curr_events = iot_os_eventgroup_wait_bits(log_ctx->events,
												  IOT_LOG_FILE_EVENT_SYNC_REQ_BIT, true, 0xffffffff);
		IOT_LOG_FILE_DEBUG("curr_events=%d\n", curr_events);

		if (curr_events == IOT_LOG_FILE_EVENT_SYNC_REQ_BIT) {
			IOT_LOG_FILE_DEBUG("_iot_log_file_is_opening()=%d\n", _iot_log_file_is_opening());
			if (_iot_log_file_is_opening() == IOT_LOG_FILE_FALSE) {
				iot_err = _iot_log_file_manager(log_ctx);
				if (iot_err != IOT_ERROR_NONE) {
					IOT_LOG_FILE_ERROR("_iot_log_file_manager err=%d", iot_err);
					return;
				}
			}
		}
	}
}
#endif

static int _iot_log_file_check_valid_range(iot_log_file_handle_t *file_handle, size_t read_size)
{
	int ret = IOT_LOG_FILE_FALSE;

	if (file_handle->cur_addr + read_size > file_handle->start_addr + file_handle->log_size) {
		ret = IOT_LOG_FILE_FALSE;
	} else {
		ret = IOT_LOG_FILE_TRUE;
	}

	IOT_LOG_FILE_DEBUG("%s ret=%d\n", __FUNCTION__, ret);

	return ret;
}

iot_log_file_handle_t *iot_log_file_open(size_t *filesize, iot_log_file_type_t file_type)
{
	iot_log_file_handle_t *file_handle = NULL;

	IOT_LOG_FILE_DEBUG("[%s]\n", __FUNCTION__);

	if (log_ctx == NULL) {
		IOT_LOG_FILE_ERROR("log_ctx is not initialized\n");
		return NULL;
	}

	file_handle = iot_os_malloc(sizeof(iot_log_file_handle_t));
	if (file_handle == NULL) {
		goto error_log_file_open;
	}

	memset(file_handle, 0, sizeof(iot_log_file_handle_t));
	file_handle->file_type = file_type;

	switch (file_type) {
#ifdef CONFIG_STDK_IOT_CORE_LOG_FILE_RAM_ONLY
	case RAM_ONLY:
		_iot_log_file_enable(IOT_LOG_FILE_FALSE);

		/* Index of RAM buf array */
		file_handle->start_addr = 0;
		file_handle->max_log_size = IOT_LOG_FILE_RAM_BUF_SIZE;
		file_handle->tail_addr = log_ctx->log_buf.cnt;

		if (log_ctx->log_buf.overridden == IOT_LOG_FILE_TRUE) {
			*filesize = IOT_LOG_FILE_RAM_BUF_SIZE;
			file_handle->cur_addr = file_handle->tail_addr;
		} else {
			*filesize = log_ctx->log_buf.cnt;
			file_handle->cur_addr = file_handle->start_addr;
		}
		file_handle->log_size = *filesize;
		break;
#endif
#ifdef CONFIG_STDK_IOT_CORE_LOG_FILE_FLASH_WITH_RAM
	case FLASH_WITH_RAM:
	{
		iot_log_file_header_state_t log_header_state;
		struct iot_log_file_header_tag log_file_header;
		_iot_log_file_open_state(IOT_LOG_FILE_TRUE);

		log_header_state = _iot_log_file_load_header(&log_file_header);
		if (log_header_state != NORMAL) {
			_iot_log_file_open_state(IOT_LOG_FILE_FALSE);
			goto error_log_file_open;
		}

		file_handle->start_addr = IOT_LOG_FILE_FLASH_ADDR + sizeof(struct iot_log_file_header_tag);
		file_handle->max_log_size = IOT_LOG_FILE_FLASH_SIZE - sizeof(struct iot_log_file_header_tag);
		file_handle->tail_addr = _iot_log_file_sector_to_addr(log_file_header.sector.num, log_file_header.sector.offset);
		if (log_file_header.written_size < file_handle->max_log_size) {
			file_handle->cur_addr = file_handle->start_addr;
		} else {
			file_handle->cur_addr = file_handle->tail_addr;
		}

		*filesize = log_file_header.written_size;
		file_handle->log_size = *filesize;
		IOT_LOG_FILE_DEBUG("file handle start=0x%x cur=0x%x end=0x%x *filesize=0x%x(%d)\n",
			file_handle->start_addr, file_handle->cur_addr, file_handle->log_size, *filesize, *filesize);
		break;
	}
#endif
	default:
		IOT_LOG_FILE_ERROR("Unsupported file_type(%d)! %s %d\n",
			file_handle->file_type, __FUNCTION__, __LINE__);
		goto error_log_file_open;
	}

	IOT_LOG_FILE_DEBUG("file handle =0x%p\n", file_handle);

	return file_handle;

error_log_file_open:
	if (file_handle != NULL) {
		iot_os_free(file_handle);
	}

	return NULL;
}

iot_error_t _iot_log_read_bytes(iot_log_file_handle_t *file_handle, void *buffer, unsigned int size)
{
	iot_error_t iot_err = IOT_ERROR_NONE;

	switch (file_handle->file_type) {
#ifdef CONFIG_STDK_IOT_CORE_LOG_FILE_RAM_ONLY
		case RAM_ONLY:
			memcpy(buffer, &log_ctx->log_buf.buf[file_handle->cur_addr], size);
			break;
#endif
#ifdef CONFIG_STDK_IOT_CORE_LOG_FILE_FLASH_WITH_RAM
		case FLASH_WITH_RAM:
			iot_err = iot_log_read_flash(file_handle->cur_addr, buffer, size);
			break;
#endif
		default:
			IOT_LOG_FILE_ERROR("Unsupported file_type(%d)! %s %d\n",
					file_handle->file_type, __FUNCTION__, __LINE__);
			iot_err = IOT_ERROR_BAD_REQ;
			break;
	}

	return iot_err;
}

iot_error_t iot_log_file_seek(iot_log_file_handle_t *file_handle, int seek_offset, unsigned int origin_addr)
{
	int new_offset;
	iot_error_t iot_err = IOT_ERROR_NONE;

	if (file_handle->log_size == 0) {
	    return IOT_ERROR_INVALID_ARGS;
	}

	switch (file_handle->file_type) {
		case RAM_ONLY:
		case FLASH_WITH_RAM:
			new_offset = ((origin_addr - file_handle->start_addr) + seek_offset) % file_handle->log_size;
			if (new_offset < 0) {
				new_offset += file_handle->log_size;
			}
			file_handle->cur_addr = file_handle->start_addr + new_offset;
			break;
		default:
			IOT_LOG_FILE_ERROR("Unsupported file_type(%d)! %s %d\n",
				file_handle->file_type, __FUNCTION__, __LINE__);
			iot_err = IOT_ERROR_BAD_REQ;
			break;
	}
	return iot_err;
}

iot_error_t iot_log_file_read(iot_log_file_handle_t *file_handle,
		void *buffer, size_t buf_size, size_t *read_size)
{
	unsigned int valid_range, old_file_handle_addr;
	size_t size_to_read, offset_size, remain_size, max_remain_size;
	size_t final_read_size = 0;
	iot_error_t iot_err = IOT_ERROR_NONE;

	if (file_handle == NULL || buffer == NULL) {
		IOT_LOG_FILE_ERROR("Invalid Args! %s %d\n", __FUNCTION__, __LINE__);
		return IOT_ERROR_INVALID_ARGS;
	}

	IOT_LOG_FILE_DEBUG("[%s] *buffer=0x%p size=%d file_handle=0x%p\n", __FUNCTION__, buffer, buf_size, file_handle);

	/* STEP1 : check if read range is valid */
	valid_range = _iot_log_file_check_valid_range(file_handle, buf_size);
	IOT_LOG_FILE_DEBUG("[%s] valid_range=%d\n", __FUNCTION__, valid_range);

	if (valid_range == IOT_LOG_FILE_TRUE) {
		iot_err = _iot_log_read_bytes(file_handle, buffer, buf_size);
		if (iot_err != IOT_ERROR_NONE) {
			goto end;
		}

		file_handle->cur_addr += buf_size;
		final_read_size = buf_size;
	} else {
		/* first read */
		offset_size = file_handle->cur_addr - file_handle->start_addr;
		size_to_read = file_handle->log_size - offset_size;

		iot_err = _iot_log_read_bytes(file_handle, buffer, size_to_read);
		if (iot_err != IOT_ERROR_NONE) {
			goto end;
		}

		final_read_size = size_to_read;
		remain_size = buf_size - size_to_read;

		max_remain_size = offset_size;
		if (remain_size > max_remain_size) {
			IOT_LOG_FILE_DEBUG("[%s] remain_size > max_remain_size\n", __FUNCTION__);
			remain_size = max_remain_size;
		}
		IOT_LOG_FILE_DEBUG("[%s] remain_size=%d\n", __FUNCTION__, remain_size);

		/* mark cur_addr for error handling & Update cur_addr */
		old_file_handle_addr = file_handle->cur_addr;
		file_handle->cur_addr = file_handle->start_addr;

		/* second read */
		iot_err = _iot_log_read_bytes(file_handle, buffer + size_to_read, remain_size);
		if (iot_err != IOT_ERROR_NONE) {
			file_handle->cur_addr = old_file_handle_addr;
			final_read_size = 0;
			goto end;
		}

		file_handle->cur_addr += remain_size;
		final_read_size += remain_size;
	}

	IOT_LOG_FILE_DEBUG("[%s] file_handle->cur_addr=0x%x\n", __FUNCTION__, file_handle->cur_addr);

end:

	if (read_size)
		*read_size = final_read_size;

	return iot_err;
}

iot_error_t iot_log_file_close(iot_log_file_handle_t *file_handle)
{
	if (file_handle == NULL) {
		IOT_LOG_FILE_ERROR("file_handle is NULL! %s %d\n",
			__FUNCTION__, __LINE__);
		return IOT_ERROR_INVALID_ARGS;
	}

	if (file_handle->file_type == FLASH_WITH_RAM) {
		_iot_log_file_open_state(IOT_LOG_FILE_FALSE);
	} else if (file_handle->file_type == RAM_ONLY) {
		_iot_log_file_enable(IOT_LOG_FILE_TRUE);
	}

	free(file_handle);
	file_handle = NULL;

	return IOT_ERROR_NONE;
}

iot_error_t iot_log_file_remove(iot_log_file_type_t type)
{
	iot_error_t iot_err = IOT_ERROR_NONE;

	switch (type) {
#ifdef CONFIG_STDK_IOT_CORE_LOG_FILE_RAM_ONLY
	case RAM_ONLY:
		_iot_log_file_clear_buf();
		break;
#endif
#ifdef CONFIG_STDK_IOT_CORE_LOG_FILE_FLASH_WITH_RAM
	case FLASH_WITH_RAM:
	{
		unsigned int i = 0;
		unsigned int erase_addr = IOT_LOG_FILE_FLASH_ADDR;
		unsigned int sector_num = IOT_LOG_FILE_FLASH_SIZE / IOT_LOG_FILE_FLASH_SECTOR_SIZE;

		if (_iot_log_file_is_opening() == IOT_LOG_FILE_TRUE) {
			IOT_LOG_FILE_ERROR("Can't remove, someone opened! %s %d\n",
				__FUNCTION__, __LINE__);
			iot_err = IOT_ERROR_BAD_REQ;
			break;
		}

		IOT_LOG_FILE_DEBUG("%s %d sector_num=%d\n", __FUNCTION__, __LINE__, sector_num);

		for (i = 0; i < sector_num; i++) {
			iot_err = iot_log_erase_sector(erase_addr / IOT_LOG_FILE_FLASH_SECTOR_SIZE);
			if (iot_err != IOT_ERROR_NONE) {
				IOT_LOG_FILE_ERROR("%s %d err=%d", __FUNCTION__, __LINE__, iot_err);
				break;
			}
			erase_addr += IOT_LOG_FILE_FLASH_SECTOR_SIZE;
		}
		break;
	}
#endif
	default:
		IOT_LOG_FILE_ERROR("Unsupported file_type(%d)! %s %d\n",
			type, __FUNCTION__, __LINE__);
		iot_err = IOT_ERROR_BAD_REQ;
		break;
	}

	return iot_err;
}

void iot_log_file_exit(void)
{
	if (log_ctx != NULL) {
		iot_os_free(log_ctx);
		log_ctx = NULL;
	}
}

iot_error_t iot_log_file_init(iot_log_file_type_t type)
{
	int ret = IOT_ERROR_NONE;

	log_ctx = iot_os_malloc(sizeof(struct iot_log_file_ctx));
	if (log_ctx == NULL) {
		IOT_LOG_FILE_ERROR("malloc struct iot_log_file_ctx fail!\n");
		ret = IOT_ERROR_MEM_ALLOC;
		goto end;
	}

	memset(log_ctx, 0, sizeof(struct iot_log_file_ctx));

	switch (type) {
#ifdef CONFIG_STDK_IOT_CORE_LOG_FILE_FLASH_WITH_RAM
	case FLASH_WITH_RAM:
		log_ctx->events = iot_os_eventgroup_create();
		if (log_ctx->events == NULL) {
			IOT_LOG_FILE_ERROR("failed to create eventgroup\n");
			ret = IOT_ERROR_MEM_ALLOC;
			goto error_task_init;
		}

		if (iot_os_thread_create(_iot_log_file_task, IOT_LOG_FILE_TASK_NAME,
							 IOT_LOG_FILE_TASK_STACK_SIZE, NULL, IOT_LOG_FILE_TASK_PRIORITY, NULL) != IOT_OS_TRUE) {
			IOT_LOG_FILE_ERROR("failed to create iot_task\n");
			ret = IOT_ERROR_MEM_ALLOC;
			goto error_task_init;
		}

		_iot_log_file_open_state(IOT_LOG_FILE_FALSE);

		log_ctx->log_buf.overridden = IOT_LOG_FILE_FALSE;

		_iot_log_file_enable(IOT_LOG_FILE_TRUE);
        break;
#endif
#ifdef CONFIG_STDK_IOT_CORE_LOG_FILE_RAM_ONLY
	case RAM_ONLY:
		log_ctx->log_buf.overridden = IOT_LOG_FILE_FALSE;

		_iot_log_file_enable(IOT_LOG_FILE_TRUE);
		break;
#endif
	default:
		IOT_LOG_FILE_ERROR("Unsupported type!\n");
		ret = IOT_ERROR_INVALID_ARGS;
		goto end;
	}

	return IOT_ERROR_NONE;

#ifdef CONFIG_STDK_IOT_CORE_LOG_FILE_FLASH_WITH_RAM
error_task_init:
	if (log_ctx->events != NULL) {
		iot_os_eventgroup_delete(log_ctx->events);
		log_ctx->events = NULL;
	}
#endif

end:
	iot_log_file_exit();

	return ret;
}

#endif
