#ifndef __TAYGA_THREAD_H
#define __TAYGA_THREAD_H

#include <sys/cdefs.h>
#include <pthread.h>
#include <netinet/in.h>
#include <unistd.h>
#include "thread.h"

#define BUFFER_COUNT (1<<15)
#define WRITER_COUNT 2		//supposed to be a power of two 
#define BIND_THREADS 1

typedef unsigned int uint;

struct sbuf_chain {
       struct sbuf *head;
       struct sbuf *tail;
       pthread_mutex_t pmtx;
};

struct buf_queue {
        uint bufcount;
        uint freecount;
		 struct sbuf_chain *xlate_chains;
	struct sbuf_chain freechain;
};

enum { 
	TRANSLATOR,
	WRITER,
};

struct sworker {
       pthread_t thread;
       pthread_cond_t has_work; 
       int type;
       struct sbuf_chain work_chain;
};

#define WALK_CHAIN(ib, FOREACH) do {\
					FOREACH \
				} while(ib->next != NULL && (ib = ib->next));

void init_buf_queue(void);
void init_workers(void);
void *translator_loop(void *arg);
void *flush_loop(void *arg);
void thread_read_from_tun(void);
void grab_free_buf(void);
void *worker_loop(void*);

#endif //__TAYGA_THREAD_H
