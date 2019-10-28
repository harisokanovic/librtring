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
 * Measures latency of messages traveling between tasks
 *
 */

#define _GNU_SOURCE

#undef NDEBUG
#include <assert.h>

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/prctl.h>

#include "rtring.h"

struct config_t {
    long int cpu_count;
    long int producer_count;
    long int consumer_count;
    int producer_per_cpu;
    int consumer_per_cpu;
    int sched_fifo_priority;
    int use_pthread;
    int quiet;
    long int period_us;
    long long int warmup_iterations;
    long long int total_iterations;
};

struct task_data_t {
    volatile int is_running;
    volatile int print_stats;
    pthread_t thread_handle;
    pid_t pid;
    long long unsigned int sample_count;
    long long unsigned int total_latency;
    long long unsigned int min_latency;
    long long unsigned int max_latency;
};

struct sample_t {
    long int magic;
    long int ignore;
    long long unsigned int timestamp;
};

#define SAMPLE_MAGIC 0xABCD12EF

struct config_t config;

const char* ring_pathname = NULL;
rtring_t *ring = NULL;

/* Shared memory, signals all tasks to stop when cleared */
volatile int *keep_running = NULL;

/* Shared memory, contains task information and results */
struct task_data_t *producer_data = NULL;
struct task_data_t *consumer_data = NULL;

void stop_signal() {
    printf(" (INTERRUPT) ");
    fflush(stdout);

    /* signal producers and consumers to stop */
    *keep_running = 0;
}

void* mmap_shared_array(size_t element_size, size_t len)
{
    size_t map_size = element_size * len;

    void* map_ptr = mmap(NULL, map_size, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_SHARED, -1, 0);
    assert(map_ptr && map_ptr != MAP_FAILED);

    memset(map_ptr, 0, map_size);

    return map_ptr;
}

void munmap_shared_array(void* map_ptr, size_t element_size, size_t len)
{
    size_t map_size = element_size * len;
    assert(munmap(map_ptr, map_size) == 0);
}

void task_start(struct task_data_t *taskdata, void *(fn_ptr)(void*), void *task_param)
{
    if (config.use_pthread) {
        assert(pthread_create(&taskdata->thread_handle, NULL, fn_ptr, task_param) == 0);
    }
    else {
        pid_t newpid = fork();
        assert(newpid >= 0);

        if (newpid == 0) {
            /* child process */

            /* ignore SIGINT, process will stop when signaled by parent */
            assert(signal(SIGINT, SIG_IGN) == stop_signal);

            /* double-cast fn_ptr() result to avoid "-Wpointer-to-int-cast" */
            int status = (int)(long int)fn_ptr(task_param);
            assert(status == 0);

            /* do not return to main */
            exit(0);
            assert(0);
        }
        else {
            /* parent process */
            taskdata->pid = newpid;
        }
    }
}

void task_join(struct task_data_t *taskdata)
{
    if (config.use_pthread) {
        assert(pthread_join(taskdata->thread_handle, NULL) == 0);
    }
    else {
        int wstatus = -1;
        pid_t res = -1;
        while (1) {
            assert(taskdata->pid > 0);
            res = waitpid(taskdata->pid, &wstatus, 0);
            if (res == -1) {
                if (errno == ECHILD)
                    break; /* child already exited */
                assert(errno == EINTR); /* and try again */
            } else if (res == taskdata->pid) {
                if (WIFEXITED(wstatus)) {
                    /* child exited */
                    assert(WEXITSTATUS(wstatus) == 0);
                    break;
                }
                /* else try again */
            } else {
                /* something strange happened */
                assert(0);
            }
        };
    }
}

void task_setname(const char *task_prefix, long int task_idx)
{
    int print_res;
    char buf[16];

    buf[0] = '\0';
    print_res = snprintf(buf, sizeof(buf), "tl-%s%ld",
        task_prefix, task_idx
        );
    buf[sizeof(buf) - 1] = '\0';
    assert(print_res > 0);

    if (config.use_pthread) {
        assert(pthread_setname_np(pthread_self(), buf) == 0);
    }
    else {
        assert(prctl(PR_SET_NAME, (unsigned long)buf, 0, 0, 0) == 0);
    }
}

void set_sched_fifo(int priority) {
    struct sched_param sp;

    assert(priority > 0);

    memset(&sp, 0, sizeof(struct sched_param));
    sp.sched_priority = priority;

    assert(sched_setscheduler(0 /* calling thread */, SCHED_FIFO, &sp) == 0);
}

void assign_to_cpu(int cpuid) {
    cpu_set_t *cpuset;
    size_t cpuset_size;

    assert(cpuid >= 0);

    cpuset = CPU_ALLOC(config.cpu_count);
    assert(cpuset);

    cpuset_size = CPU_ALLOC_SIZE(config.cpu_count);
    assert(cpuset_size > 0);

    CPU_ZERO_S(cpuset_size, cpuset);
    CPU_SET_S(cpuid, cpuset_size, cpuset);

    assert(sched_setaffinity(0 /* calling thread */, cpuset_size, cpuset) == 0);

    CPU_FREE(cpuset);
}

long long unsigned int get_time_us() {
    struct timespec ts;
    long long unsigned int res_us;

    assert(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);

    res_us  = ((long long unsigned int)ts.tv_sec) * 1000000ULL;
    res_us += ((long long unsigned int)ts.tv_nsec) / 1000ULL;

    return res_us;
}

void sleep_us(long int period_us) {
    struct timespec ts;

    ts.tv_sec = 0;
    ts.tv_nsec = period_us * 1000L;
    assert(ts.tv_nsec <= 999999999L);

    assert(clock_nanosleep(CLOCK_MONOTONIC, 0, &ts, &ts) == 0);
}

void print_latency_stats(const struct task_data_t *taskdata, long int consumer_id) {
    int count = 0;
    int print_res;
    unsigned long long int sample_count;

    if (consumer_id >= 0) {
        print_res = printf(" c%ld", consumer_id);
        assert(print_res > 0);
        count += print_res;
    }

    sample_count = taskdata->sample_count;
    if (!sample_count)
        sample_count = 1;

    print_res = printf(
        " samples=%llu, average=%llu us, min=%llu us, max=%llu us",
        taskdata->sample_count,
        (taskdata->total_latency / sample_count),
        taskdata->min_latency,
        taskdata->max_latency
        );
    assert(print_res > 0);
    count += print_res;

    for (; count < 70; ++count)
        printf(" ");

    printf("\n");
}

void produce_one(rtring_t *local_ring, long int ignore, int blocking) {
    uint32_t write_res;
    struct sample_t sample;

    sample.timestamp = get_time_us();
    sample.ignore = ignore;
    sample.magic = SAMPLE_MAGIC;

    errno = -42;
    write_res = rtring_write(local_ring, &sample, sizeof(struct sample_t), 1,
        (blocking ? 0 : RTRING_NON_BLOCKING));

    if (write_res == 0) {
        if (blocking) {
            assert(errno == EINTR);
        }
        else {
            /* ring is full */
            /* TODO rtring should set errno when full and non-blocking */
            assert(errno == -42);
        }
    }
    else if (write_res == 1) {
        /* librtpi has EAGAIN loop */
        assert(errno == -42 || errno == EAGAIN);
    }
    else {
        assert(0 /* unexpected write_res */);
    }

    /* we may skip an iteration when interrupted so that
     * caller can re-evaluate keep_running
     */
}

long long unsigned int consume_one(rtring_t *local_ring) {
    long long unsigned int flight_time_us = 0;
    long long unsigned int current_time_us;
    uint32_t read_res;
    struct sample_t sample;

    errno = -42;
    read_res = rtring_read(local_ring, &sample, sizeof(struct sample_t), 1, 0);

    assert( (read_res == 1 && (errno == -42 || errno == EAGAIN)) || (read_res == 0 && errno == EINTR) );

    if (read_res) {
        assert(sample.magic == SAMPLE_MAGIC);

        if (!sample.ignore) {
            current_time_us = get_time_us();

            if (current_time_us >= sample.timestamp)
                flight_time_us = current_time_us - sample.timestamp;
            else /* unlikely: clock wrapped around */
                flight_time_us = (((long long unsigned int)-1) - sample.timestamp) + current_time_us;
        }
    }

    /* we may skip an iteration when interrupted so that
     * caller can re-evaluate keep_running
     */

    return flight_time_us;
}

void *producer_main(void *param) {
    const long int producer_id = (long int)param;
    struct task_data_t * const taskdata = &producer_data[producer_id];
    long long unsigned int itr = 0;
    rtring_t *local_ring = NULL;

    task_setname("p", producer_id);

    if (config.sched_fifo_priority)
        set_sched_fifo(config.sched_fifo_priority);

    if (config.producer_per_cpu)
        assign_to_cpu(producer_id % config.cpu_count);

    if (ring_pathname) {
        local_ring = rtring_open(ring_pathname, sizeof(struct sample_t), 1, 0);
        assert(local_ring);
    }
    else {
        local_ring = ring;
    }

    while (*keep_running) {
        produce_one(local_ring,
            itr <= config.warmup_iterations /* ignore warmup iterations */,
            1 /* blocking */
            );

        sleep_us(config.period_us);

        if (config.total_iterations > 0 && itr >= config.total_iterations)
            break;

        ++itr;
    }

    if (ring_pathname)
        assert(rtring_close(local_ring) == 0);

    taskdata->is_running = 0;

    return NULL;
}

void *consumer_main(void *param) {
    const long int consumer_id = (long int)param;
    const long int next_consumer_id = (consumer_id + 1) % config.consumer_count;
    struct task_data_t * const taskdata = &consumer_data[consumer_id];
    long long unsigned int sample_delta_us = 0;
    rtring_t *local_ring = NULL;

    task_setname("c", consumer_id);

    if (config.sched_fifo_priority)
        set_sched_fifo(config.sched_fifo_priority);

    if (config.consumer_per_cpu)
        assign_to_cpu(consumer_id % config.cpu_count);

    if (ring_pathname) {
        local_ring = rtring_open(ring_pathname, sizeof(struct sample_t), 1, 0);
        assert(local_ring);
    }
    else {
        local_ring = ring;
    }

    while (*keep_running) {
        sample_delta_us = consume_one(local_ring);

        if (sample_delta_us) {
            ++taskdata->sample_count;
            taskdata->total_latency += sample_delta_us;

            if (sample_delta_us < taskdata->min_latency)
                taskdata->min_latency = sample_delta_us;

            if (sample_delta_us > taskdata->max_latency)
                taskdata->max_latency = sample_delta_us;
        }

        if (taskdata->print_stats) {
            print_latency_stats(taskdata, consumer_id);
            assert(fflush(stdout) == 0);

            taskdata->print_stats = 0;

            if (next_consumer_id == 0) {
                /* move cursor to overwrite old status */
                for (long int itr = 0; itr < config.consumer_count; ++itr)
                    printf("\033[A");

                assert(fflush(stdout) == 0);
            }

            /* arm next consumer to print */
            consumer_data[next_consumer_id].print_stats = 1;
        }
    }

    if (ring_pathname)
        assert(rtring_close(local_ring) == 0);

    taskdata->is_running = 0;

    return NULL;
}

int main(int argc, const char** argv)
{
    /* set default config options */
    memset(&config, 0, sizeof(struct config_t));
    config.cpu_count = sysconf(_SC_NPROCESSORS_ONLN);
    assert(config.cpu_count > 0);
    config.producer_count = config.cpu_count;
    config.consumer_count = config.cpu_count;
    config.producer_per_cpu = 1;
    config.consumer_per_cpu = 1;
    config.period_us = 997;
    config.warmup_iterations = 10;
    config.total_iterations = 100;

    for (int itr = 1; itr < argc; itr += 2) {
        const char *arg = argv[itr];
        assert(itr + 1 < argc);
        const char *val = argv[itr + 1];

        if (strcmp(arg, "--ring-file") == 0) {
            ring_pathname = val;
            if (ring_pathname[0] == '\0')
                ring_pathname = NULL;
        }
        else if (strcmp(arg, "--quiet") == 0) {
            config.quiet = atoi(val);
            assert(config.quiet == 0 || config.quiet == 1);
        }
        else if (strcmp(arg, "--period") == 0) {
            config.period_us = atol(val);
            assert(config.period_us > 0);
        }
        else if (strcmp(arg, "--warmup-iterations") == 0) {
            config.warmup_iterations = atoll(val);
            assert(config.warmup_iterations > 0);
        }
        else if (strcmp(arg, "--iterations") == 0) {
            config.total_iterations = atoll(val);
            assert(config.total_iterations == -1 || config.total_iterations > 0);
        }
        else if (strcmp(arg, "--rt-priority") == 0) {
            config.sched_fifo_priority = atoi(val);
            assert(config.sched_fifo_priority > 0);
        }
        else if (strcmp(arg, "--use-pthread") == 0) {
            config.use_pthread = atoi(val);
            assert(config.use_pthread == 0 || config.use_pthread == 1);
        }
        else {
            printf("ERROR: Bad arg: %s\n", arg);
            assert(0);
        }
    }

    assert(config.total_iterations <= 0 || config.warmup_iterations < config.total_iterations);

    if (config.total_iterations > 0)
        printf("Running test for %lld iterations...\n", config.total_iterations);
    else
        printf("Running test, send SIGINT to stop...\n");

    assert(fflush(stdout) == 0);
    assert(fflush(stderr) == 0);

    if (config.sched_fifo_priority)
        assert(mlockall(MCL_CURRENT|MCL_FUTURE) == 0);

    ring = rtring_open(ring_pathname, sizeof(struct sample_t), 1, RTRING_INIT);
    assert(ring);

    keep_running = (volatile int*)mmap_shared_array(sizeof(int), 1);
    *keep_running = 1;

    assert(signal(SIGINT, stop_signal) != SIG_ERR);

    producer_data = (struct task_data_t*)mmap_shared_array(sizeof(struct task_data_t), config.producer_count);
    consumer_data = (struct task_data_t*)mmap_shared_array(sizeof(struct task_data_t), config.consumer_count);

    /* init consumer_data */
    for (long int itr = 0; itr < config.consumer_count; ++itr) {
        consumer_data[itr].is_running = 1;
        consumer_data[itr].min_latency = (long long unsigned int)-1;
    }

    if (!config.quiet) {
        /* arm first consumer to start printing */
        consumer_data[0].print_stats = 1;
    }

    /* start producers */
    for (long int itr = 0; itr < config.producer_count; ++itr)
        task_start(&producer_data[itr], producer_main, (void*)itr);

    /* start consumers */
    for (long int itr = 0; itr < config.consumer_count; ++itr)
        task_start(&consumer_data[itr], consumer_main, (void*)itr);

    /* wait for all producers to finish */
    for (long int itr = 0; itr < config.producer_count; ++itr)
        task_join(&producer_data[itr]);

    /* signal consumers to stop */
    *keep_running = 0;

    /* wait for all consumers to finish, pump ignorable messages */
    for (long int itr = 0; itr < config.consumer_count; ++itr) {
        while (consumer_data[itr].is_running) {
            produce_one(ring, 1 /* ignore */, 0 /* not blocking */);
            sleep_us(1000 /* 1 ms */);
        }

        task_join(&consumer_data[itr]);
    }

    assert(fflush(stdout) == 0);
    assert(fflush(stderr) == 0);

    /* printing extra whitespace to overwrite buffer */
    printf("                                                                      \n");

    printf("Latency results per consumer:                                         \n");
    for (long int itr = 0; itr < config.consumer_count; ++itr) {
        print_latency_stats(&consumer_data[itr], itr);
    }
    printf("                                                                      \n");

    struct task_data_t overall;
    memset(&overall, 0, sizeof(struct task_data_t));
    overall.min_latency = (long long unsigned int)-1;
    for (long int itr = 0; itr < config.consumer_count; ++itr) {
        overall.sample_count += consumer_data[itr].sample_count;
        overall.total_latency += consumer_data[itr].total_latency;

        if (consumer_data[itr].min_latency < overall.min_latency)
            overall.min_latency = consumer_data[itr].min_latency;
    
        if (consumer_data[itr].max_latency > overall.max_latency)
            overall.max_latency = consumer_data[itr].max_latency;
    }

    printf("Overall latency results:                                              \n");
    print_latency_stats(&overall, -1);
    printf("                                                                      \n");

    munmap_shared_array(consumer_data, sizeof(struct task_data_t), config.consumer_count);
    consumer_data = NULL;

    munmap_shared_array(producer_data, sizeof(struct task_data_t), config.producer_count);
    producer_data = NULL;

    assert(signal(SIGINT, SIG_DFL) == stop_signal);

    munmap_shared_array((void*)keep_running, sizeof(int), 1);
    keep_running = NULL;

    assert(rtring_close(ring) == 0);
    ring = NULL;

    return 0;
}
