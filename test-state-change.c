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
 * Check internal ring state after read/write operations
 *
 */

#undef NDEBUG
#include <assert.h>

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rtring.h"

const char* ring_pathname = NULL;
rtring_t *ring = NULL;

void assert_state(uint32_t tail, uint32_t head, uint32_t writeable_space, uint32_t readable_space)
{
    assert(ring->tail == tail);
    assert(ring->head == head);
    assert(rtring_writeable(ring, RTRING_NON_BLOCKING) == writeable_space);
    assert(rtring_readable(ring, RTRING_NON_BLOCKING) == readable_space);
}

void assert_read_fail()
{
    unsigned char numb = 0;
    assert(rtring_read(ring, &numb, 1, 1, RTRING_NON_BLOCKING) == 0);
}

void assert_read_numb(unsigned char expected_numb)
{
    unsigned char numb = ~expected_numb;
    assert(rtring_read(ring, &numb, 1, 1, RTRING_NON_BLOCKING) == 1);
    assert(numb == expected_numb);
}

void assert_write_fail()
{
    unsigned char byte = 0xFF;
    assert(rtring_write(ring, &byte, 1, 1, RTRING_NON_BLOCKING) == 0);
}

void assert_write_numb(unsigned char numb)
{
    assert(rtring_write(ring, &numb, 1, 1, RTRING_NON_BLOCKING) == 1);
}

void assert_write_everything(uint32_t count)
{
    while (count) {
        unsigned char byte = 0xFF;
        assert(rtring_write(ring, &byte, 1, 1, RTRING_NON_BLOCKING) == 1);
        --count;
    }
}

void assert_read_everything(uint32_t count)
{
    while (count) {
        unsigned char byte = 0;
        assert(rtring_read(ring, &byte, 1, 1, RTRING_NON_BLOCKING) == 1);
        --count;
    }
}

int main(int argc, const char** argv)
{
    for (int itr = 1; itr < argc; itr += 2) {
        const char *arg = argv[itr];
        assert(itr + 1 < argc);
        const char *val = argv[itr + 1];

        if (strcmp(arg, "--ring-file") == 0) {
            ring_pathname = val;
            if (ring_pathname[0] == '\0')
                ring_pathname = NULL;
        }
        else {
            printf("ERROR: Bad arg: %s\n", arg);
            assert(0);
        }
    }

    ring = rtring_open(ring_pathname, 1, 1, RTRING_INIT);
    assert(ring);

    assert(ring->page_size >= 7);
    assert(ring->buff_pages == 1);

    assert_state(0, 0, ring->page_size - 1, 0);

    assert_read_fail();
    assert_state(0, 0, ring->page_size - 1, 0);

    assert_write_numb(101);
    assert_state(0, 1, ring->page_size - 2, 1);

    assert_read_numb(101);
    assert_state(1, 1, ring->page_size - 1, 0);

    assert_read_fail();
    assert_state(1, 1, ring->page_size - 1, 0);

    assert_write_numb(201);
    assert_state(1, 2, ring->page_size - 2, 1);

    assert_write_numb(202);
    assert_state(1, 3, ring->page_size - 3, 2);

    assert_read_numb(201);
    assert_state(2, 3, ring->page_size - 2, 1);

    assert_read_numb(202);
    assert_state(3, 3, ring->page_size - 1, 0);

    assert_read_fail();
    assert_state(3, 3, ring->page_size - 1, 0);

    assert_write_everything(ring->page_size * ring->buff_pages - 1);
    assert_state(3, 2, 0, ring->page_size - 1);

    assert_write_fail();
    assert_state(3, 2, 0, ring->page_size - 1);

    assert_read_numb(0xFF);
    assert_state(4, 2, 1, ring->page_size - 2);

    assert_write_numb(101);
    assert_state(4, 3, 0, ring->page_size - 1);

    assert_read_numb(0xFF);
    assert_state(5, 3, 1, ring->page_size - 2);

    assert_read_numb(0xFF);
    assert_state(6, 3, 2, ring->page_size - 3);

    assert_write_numb(102);
    assert_state(6, 4, 1, ring->page_size - 2);

    assert_write_numb(103);
    assert_state(6, 5, 0, ring->page_size - 1);

    assert_read_everything(ring->page_size * ring->buff_pages - 1);
    assert_state(5, 5, ring->page_size - 1, 0);

    assert(rtring_close(ring) == 0);
    ring = NULL;

    return 0;
}
