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
 * Check mirrored memory mapping works
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

    uint8_t *mem = (uint8_t *)ring;

    uint32_t page_size = ring->page_size;
    assert(page_size > 0);

    uint32_t buff_pages = ring->buff_pages;
    assert(buff_pages == 1);

    /* verify mirror allocation works */
    /* TODO: mirror doesn't work with memfd's */
    *((uint32_t*)(mem + page_size)) = 12345;
    assert(*((uint32_t*)(mem + page_size)) == 12345);
    assert(*((uint32_t*)(mem + page_size + page_size)) == 12345);

    *((uint32_t*)(mem + page_size)) = 789123;
    assert(*((uint32_t*)(mem + page_size)) == 789123);
    assert(*((uint32_t*)(mem + page_size + page_size)) == 789123);

    assert(rtring_close(ring) == 0);
    ring = NULL;

    return 0;
}
