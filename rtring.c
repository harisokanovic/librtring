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
 * rtring implementation
 *
 */

#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <rtpi.h>

#include <sys/mman.h>

#include "rtring.h"

static uint32_t rtring_page_size()
{
    long page_size = sysconf(_SC_PAGE_SIZE);
    if (page_size < 0)
        page_size = 0;
    return page_size;
}

static void *rtring_mmap(int fd, uint32_t page_size, uint32_t buff_pages, uint32_t allocation_size, int shared)
{
    void *ring = NULL;
    void *buff_a, *buff_b, *pret;
    int map_prot, map_flags;

    if (shared)
        map_flags = MAP_SHARED;
    else
        map_flags = MAP_PRIVATE;

    pret = mmap(NULL, allocation_size, PROT_READ|PROT_WRITE, map_flags, fd, 0);
    if (pret == MAP_FAILED)
        goto err;

    assert(pret);

    ring = pret;
    buff_a = ring + page_size;
    buff_b = buff_a + page_size*buff_pages;

    pret = mmap(buff_b, page_size*buff_pages, PROT_READ|PROT_WRITE, map_flags|MAP_FIXED, fd, page_size);
    if (pret == MAP_FAILED)
        goto err;
    else if (pret != buff_b) {
        /* unlikely: mmap might move the allocation */
        munmap(pret, page_size*buff_pages);
        errno = EINVAL;
        goto err;
    }

    assert(pret == buff_b);

    return ring;

err:
    if (ring)
        munmap(ring, allocation_size);

    return NULL;
}

static int rtring_init_mem(void *ring_mem, uint32_t page_size, uint32_t buff_pages, uint32_t element_size, int shared)
{
    rtring_t *ring = (rtring_t *)ring_mem;
    int mutex_flags, cond_flags;

    memset(ring_mem, 0, page_size*(buff_pages + 1));
    /* TODO check overflow */

    if (shared) {
        mutex_flags = RTPI_MUTEX_PSHARED;
        cond_flags = RTPI_COND_PSHARED; /* TODO: doesn't work with file fd's */
    }
    else {
        mutex_flags = 0;
        cond_flags = 0;
    }

    if (pi_mutex_init(&ring->mutex, mutex_flags))
        goto err;
    if (pi_cond_init(&ring->producer_cond, cond_flags))
        goto err_noconds;
    if (pi_cond_init(&ring->consumer_cond, cond_flags))
        goto cons_onecond;

    ring->page_size = page_size;
    ring->buff_pages = buff_pages;
    ring->element_size = element_size;

    ring->magic = RTRING_MAGIC;

    return 0;

cons_onecond:
    pi_cond_destroy(&ring->producer_cond, &ring->mutex);
err_noconds:
    pi_mutex_destroy(&ring->mutex);
err:
    return 1;
}

static int rtring_check_mem(const void *ring_mem, uint32_t expected_page_size, uint32_t expected_buff_pages, uint32_t expected_element_size)
{
    const rtring_t *ring = (rtring_t *)ring_mem;

    if (ring->magic != RTRING_MAGIC
        || ring->page_size < 1 || ring->page_size != expected_page_size 
        || ring->buff_pages < 1 || ring->buff_pages != expected_buff_pages
        || ring->element_size < 1 || ring->element_size != expected_element_size
        )
    {
        errno = EINVAL;
        return 1;
    }

    return 0;
}

rtring_t *rtring_open(const char* pathname, uint32_t size, uint32_t count, uint32_t flags)
{
    rtring_t *ring = NULL;
    void *mem = NULL;
    int fd = -1;
    int shared = (pathname != NULL);
    uint32_t page_size, buff_pages, allocation_size;

    if (!size || !count || flags & ~((uint32_t)RTRING_INIT)) {
        errno = EINVAL;
        goto end;
    }

    page_size = rtring_page_size();
    if (!page_size)
        goto end;

    if (sizeof(rtring_t) > page_size) {
        /* unlikely: rtring_t must fit in one page */
        errno = EINVAL;
        goto end;
    }

    /* TODO check overflow */
    allocation_size = size * count;
    buff_pages = allocation_size / page_size;
    if (allocation_size % page_size)
        ++buff_pages;

    /* TODO check overflow */
    allocation_size = page_size + page_size*buff_pages*2;

    /* TODO mirrored mapping fails with memfd, disallow until it's fixed */
    if (!pathname) {
        errno = EINVAL;
        goto end;
    }

    if (pathname)
        fd = open(pathname, O_RDWR|O_CREAT, 0644);
    else
        fd = memfd_create("anon_rtring", 0);
    if (fd < 0)
        goto end;

    /* sets fd size to allocation_size, zero fills missing bytes
     * TODO: fail if already mapped > allocation_size?
     */
    if (ftruncate(fd, allocation_size))
        goto end;

    mem = rtring_mmap(fd, page_size, buff_pages, allocation_size, shared);
    if (!mem)
        goto end;

    if (flags & RTRING_INIT) {
        if (rtring_init_mem(mem, page_size, buff_pages, size, shared))
            goto end;
    }
    else {
        if (rtring_check_mem(mem, page_size, buff_pages, size))
            goto end;
    }

    ring = (rtring_t *)mem;
    mem = NULL;

end:
    if (mem)
        munmap(mem, allocation_size);
    if (fd >= 0)
        close(fd);

    return ring;
}

int rtring_close(rtring_t *ring)
{
    uint32_t page_size, allocation_size;

    /* freeing NULL is OK */
    if (!ring)
        goto end_success;

    page_size = rtring_page_size();
    if (!page_size)
        goto end_error;

    if (rtring_check_mem(ring, page_size, ring->buff_pages, ring->element_size))
        goto end_error;

    /* Cannot run pi_mutex_destroy() and pi_cond_destroy() since other
     *  tasks may be using them. Just unmap the allocation.
     */

    /* TODO check overflow */
    allocation_size = ring->page_size + ring->page_size*ring->buff_pages*2;

    if (munmap(ring, allocation_size))
        goto end_error;

end_success:
    return 0;

end_error:
    return -1;
}

static int rtring_mutex_lock(rtring_t *ring, uint32_t flags)
{
    if (flags & RTRING_NON_BLOCKING)
        return pi_mutex_trylock(&ring->mutex);
    else
        return pi_mutex_lock(&ring->mutex);
}

static uint32_t rtring_writeable_nolock(rtring_t *ring)
{
    /* Deduct 1 byte to guard against premature head/tail inversion.
     * We otherwise cannot differentiate between empty and full buffers.
     */
    if (ring->head >= ring->tail)
        return (ring->page_size*ring->buff_pages) + ring->tail - ring->head - 1;
    else
        return ring->tail - ring->head - 1;
}

static uint32_t rtring_readable_nolock(rtring_t *ring)
{
    if (ring->head >= ring->tail)
        return ring->head - ring->tail;
    else
        return (ring->page_size*ring->buff_pages) + ring->head - ring->tail;
}

uint32_t rtring_writeable(rtring_t *ring, uint32_t flags)
{
    uint32_t res = (uint32_t)-1;

    if (!ring || flags & ~((uint32_t)RTRING_NON_BLOCKING)) {
        errno = EINVAL;
        goto out_nolock;
    }

    if (rtring_mutex_lock(ring, flags))
        goto out_nolock;

    res = rtring_writeable_nolock(ring);

    pi_mutex_unlock(&ring->mutex); /* TODO result? */

out_nolock:
    return res;
}

uint32_t rtring_readable(rtring_t *ring, uint32_t flags)
{
    uint32_t res = (uint32_t)-1;

    if (!ring || flags & ~((uint32_t)RTRING_NON_BLOCKING)) {
        errno = EINVAL;
        goto out_nolock;
    }

    if (rtring_mutex_lock(ring, flags))
        goto out_nolock;

    res = rtring_readable_nolock(ring);

    pi_mutex_unlock(&ring->mutex); /* TODO result? */

out_nolock:
    return res;
}

static uint32_t rtring_mem_copy(uint8_t *dst, uint32_t dst_size, const uint8_t *src, uint32_t src_size)
{
    if (dst_size > src_size)
        dst_size = src_size;

    memcpy(dst, src, dst_size);

    return dst_size;
}

uint32_t rtring_write(rtring_t *ring, const void* ptr, uint32_t size, uint32_t count, uint32_t flags)
{
    uint32_t copied = 0;
    uint32_t sz, elm_sz;

    if (!ring || ((size|count) && !ptr) || flags & ~((uint32_t)RTRING_NON_BLOCKING)) {
        errno = EINVAL;
        goto out_nolock;
    }

    if (rtring_mutex_lock(ring, flags))
        goto out_nolock;

    if (size != ring->element_size) {
        errno = EINVAL;
        goto out;
    }

again:
    sz = rtring_writeable_nolock(ring);
    sz -= sz % size;

    if (sz) {
        elm_sz = size*count;

        sz = rtring_mem_copy(
            ((void *)ring + ring->page_size + ring->head), sz,
            ptr, elm_sz);

        ring->head = (ring->head + sz) % (ring->page_size*ring->buff_pages);

        ptr += sz;

        elm_sz = sz/size;
        count -= elm_sz;
        copied += elm_sz;

        /* signal consumers now that we've written data */
        if (pi_cond_signal(&ring->consumer_cond, &ring->mutex))
            goto out;
    }

    if (count && !(flags & RTRING_NON_BLOCKING)) {
        /* wait for more free space */
        if (pi_cond_wait(&ring->producer_cond, &ring->mutex))
            goto out;

        goto again; /* try again after waiting */
    }

out:
    pi_mutex_unlock(&ring->mutex); /* TODO result? */
out_nolock:
    return copied;
}

uint32_t rtring_read(rtring_t *ring, void* ptr, uint32_t size, uint32_t count, uint32_t flags)
{
    uint32_t copied = 0;
    uint32_t sz, elm_sz;

    if (!ring || ((size|count) && !ptr) || flags & ~((uint32_t)RTRING_NON_BLOCKING)) {
        errno = EINVAL;
        goto out_nolock;
    }

    if (rtring_mutex_lock(ring, flags))
        goto out_nolock;

    if (size != ring->element_size) {
        errno = EINVAL;
        goto out;
    }

again:
    sz = rtring_readable_nolock(ring);
    sz -= sz % size;

    if (sz) {
        elm_sz = size*count;

        sz = rtring_mem_copy(
            ptr, elm_sz,
            ((void *)ring + ring->page_size + ring->tail), sz);

        ring->tail = (ring->tail + sz) % (ring->page_size*ring->buff_pages);

        ptr += sz;

        elm_sz = sz/size;
        count -= elm_sz;
        copied += elm_sz;

        /* signal producers after freeing space */
        if (pi_cond_signal(&ring->producer_cond, &ring->mutex))
            goto out;
    }

    if (count && !(flags & RTRING_NON_BLOCKING)) {
        /* wait for more data */
        if (pi_cond_wait(&ring->consumer_cond, &ring->mutex))
            goto out;

        goto again; /* try again after waiting */
    }

out:
    pi_mutex_unlock(&ring->mutex); /* TODO result? */
out_nolock:
    return copied;
}
