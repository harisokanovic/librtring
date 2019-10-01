/**
 * @file
 * @author Haris Okanovic <haris.okanovic@ni.com>
 *
 * @section LICENSE
 *
 * Copyright (c) 2019, National Instruments Corp.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * @section DESCRIPTION
 *
 * rtring API
 *
 */

#ifndef RTRING_H
#define RTRING_H

#include <rtpi.h>
#include <inttypes.h>

struct rtring {
	uint64_t magic; /* for memory-mapped file identification */

	uint32_t page_size;
	uint32_t buff_pages;
	uint32_t element_size;

	pi_mutex_t mutex;
	pi_cond_t producer_cond;
	pi_cond_t consumer_cond;

	uint32_t head;
	uint32_t tail;
};

typedef struct rtring rtring_t;

#define RTRING_MAGIC 0x525452494e470000 /* ASCII "RTRING\0\0" */

#define RTRING_INIT 0x1
#define RTRING_NON_BLOCKING 0x2

rtring_t *rtring_open(const char* pathname, uint32_t size, uint32_t count, uint32_t flags);
int rtring_close(rtring_t *ring);
uint32_t rtring_writeable(rtring_t *ring, uint32_t flags);
uint32_t rtring_readable(rtring_t *ring, uint32_t flags);
uint32_t rtring_write(rtring_t *ring, const void* ptr, uint32_t size, uint32_t count, uint32_t flags);
uint32_t rtring_read(rtring_t *ring, void* ptr, uint32_t size, uint32_t count, uint32_t flags);

#endif /* RTRING_H */
