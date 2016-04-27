#include "thread.h"
#include "tayga.h"
#include <pthread.h>
#include <pthread_np.h>
#include <sys/cdefs.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/sysctl.h>
#include <assert.h>

#ifdef __FreeBSD__
#include <netinet/tcp.h>
#include <netinet/udp.h>
#endif

extern struct config *gcfg;
extern time_t now;

static inline void __add_to_chain(sbuf_t *head, sbuf_t *tail, struct sbuf_chain *chain)
{
	if (chain->tail != NULL) {
		chain->tail->next = head;
	} else {
		chain->head = head;
	}
	chain->tail = tail;
	chain->tail->next = NULL;
}

static inline void ret_free_chain(sbuf_t *head, sbuf_t *tail, size_t len)
{
	struct buf_queue *bq = gcfg->bq;

	pthread_mutex_lock(&bq->freechain.pmtx);
	tail->next = bq->freechain.head;
	bq->freechain.head = head;
	if(bq->freechain.tail == NULL) 
		bq->freechain.tail = tail;

	bq->freecount += len;
	pthread_mutex_unlock(&bq->freechain.pmtx);
}

static inline void grab_free_chain(sbuf_t **sb, sbuf_t **tail, uint *len) 
{
	struct buf_queue *bq = gcfg->bq;

	pthread_mutex_lock(&bq->freechain.pmtx);
	*sb = bq->freechain.head;
	bq->freechain.head = NULL;
	*tail = bq->freechain.tail;
	bq->freechain.tail = NULL;
	*len = bq->freecount;
	bq->freecount = 0;
	pthread_mutex_unlock(&bq->freechain.pmtx);
}

static inline void enq_chain_to_translate(sbuf_t *head, sbuf_t *tail)
{
	struct sworker *translator = &gcfg->translator;
	struct sbuf_chain *chain = &translator->work_chain;

	pthread_mutex_lock(&chain->pmtx);
	__add_to_chain(head, tail, chain);
	pthread_cond_signal(&translator->has_work);
	pthread_mutex_unlock(&chain->pmtx);
}

static inline uint calc_handler_id(sbuf_t *sb)
{
	size_t id = 0;
	size_t i;
	union hdr_u *hdr = (union hdr_u*) sb->recv_buf;
	struct tun_pi *pi = (struct tun_pi*) sb->recv_buf;
	void *l4hdr;
	uint8_t l4proto;
	struct tcphdr *tcp;
	struct udphdr *udp;

	switch (TUN_GET_PROTO(pi)) {
	case ETH_P_IP:
		l4proto = hdr->header4.ip4.proto;
		l4hdr = ((uint8_t *) &hdr->header4 + sizeof(hdr->header4));
		id += hdr->header4.ip4.src.s_addr + hdr->header4.ip4.dest.s_addr;
		break;

	case ETH_P_IPV6:
		l4proto = hdr->header6.ip6.next_header;
		l4hdr = ((uint8_t *) &hdr->header6 + sizeof(hdr->header6) - sizeof(hdr->header6.ip6_frag));

		for (i = 0; i < sizeof(hdr->header6.ip6.src); i++)
			id += hdr->header6.ip6.src.s6_addr[i];

		for (i = 0; i < sizeof(hdr->header6.ip6.dest); i++)
			id += hdr->header6.ip6.dest.s6_addr[i];
		break;
	}

	switch(l4proto) {
	case IPPROTO_TCP:
		tcp = l4hdr;
		id += htons(tcp->th_sport) + htons(tcp->th_dport);
		break;

	case IPPROTO_UDP:
		udp = l4hdr;
		id += htons(udp->uh_sport) + htons(udp->uh_dport);
		break;
	}

	return id % gcfg->writer_count;
}

static void enq_chain_to_flush(sbuf_t *head, sbuf_t *tail)
{
	sbuf_t *si, *_si;
	uint wid, i;
	struct sworker *worker;
	struct sbuf_chain *xlc, *xlate_chains;
	xlate_chains = gcfg->bq->xlate_chains;

	si = head;
	tail->next = NULL;
	do {
		_si = si->next;
		wid = calc_handler_id(si);
		__add_to_chain(si, si, &xlate_chains[wid]);
	} while(_si != NULL && (si = _si));

	for(i = 0; i < gcfg->writer_count; ++i) {
		worker = &gcfg->writers[i];
		xlc = &xlate_chains[i];	

		if(xlc->head == NULL)
			continue;

	   pthread_mutex_lock(&worker->work_chain.pmtx);
	   __add_to_chain(xlc->head, xlc->tail, &worker->work_chain);
	   pthread_cond_signal(&worker->has_work);
	   pthread_mutex_unlock(&worker->work_chain.pmtx);
	}
	memset(xlate_chains, 0, sizeof(struct sbuf_chain)*gcfg->writer_count);
}


static inline void __grab_sbuf_chain(sbuf_t **sb, struct sbuf_chain *chain)
{
	*sb = chain->head;
	chain->head = chain->tail = NULL;
}

static void bind_thread(pthread_t t, uint np) {
	cpuset_t cset;
	CPU_ZERO(&cset);
	CPU_SET(np,&cset);
	if(pthread_setaffinity_np(t, sizeof(cpuset_t), &cset)) {
		slog(LOG_CRIT, "Error: unable to bind thread %u to cpu %u: %s", *((uint*) t), np, strerror(errno));
		exit(1);
	}
}

static int num_cpu() {
	int ret;
	int mib[4];
	size_t len = sizeof(ret); 

	/* set the mib for hw.ncpu */
	mib[0] = CTL_HW;
	mib[1] = HW_NCPU;
	sysctl( mib, 2, &ret, &len, NULL, 0 );

	if (ret < 1)
		ret = 1;

	return ret;
}

void init_buf_queue()
{
	struct buf_queue *bq;
	struct sbuf *sb;
	uint i, sbuf_size;

	gcfg->recv_buf_size = gcfg->mtu + sizeof(struct tun_pi) + 2;
	sbuf_size = sizeof(struct sbuf) + (size_t) gcfg->recv_buf_size;
	if ((bq = calloc(1,sizeof(struct buf_queue))) != NULL) {
		bq->freechain.head = calloc(gcfg->buffer_count, sbuf_size);
		bq->xlate_chains = calloc(gcfg->writer_count, sizeof(struct sbuf_chain));
	}

	if (! bq || ! bq->freechain.head || ! bq->xlate_chains ) {
		slog(LOG_CRIT, "Error: unable to allocate %d bytes for "
								"receive buffer\n", gcfg->buffer_count*gcfg->recv_buf_size);
				exit(1);
	} 
	
	if ( pthread_mutex_init(&bq->freechain.pmtx, 0)) {
		slog(LOG_CRIT, "Error: unable to init receive queue mutex");
				exit(1);
	}

	for(sb=bq->freechain.head, i=0; i < gcfg->buffer_count-1; ++i) {
		sb->next = (struct sbuf *) ((unsigned long) sb + sbuf_size); 
		sb = sb->next;
	}
	sb->next = NULL;
	bq->freechain.tail = sb;
	bq->freecount = gcfg->buffer_count;
	bq->bufcount = gcfg->buffer_count;
	gcfg->bq=bq;
}

void init_workers(void)
{
	struct sworker *worker;
	uint i;
	uint name_len = 32;
	char name[name_len];
	int cpu_num, bind_offset = num_cpu() - gcfg->writer_count - 2; // writers plus translator and reader
	
	if (bind_offset < 0) {
		slog(LOG_CRIT, "Error: number of cores lesser than number of threads");
		exit(1);
	}
	
	if (!(gcfg->writers = calloc(gcfg->writer_count, sizeof(struct sworker)))) {
		slog(LOG_CRIT, "Error: unable to alloc memory for thread", name);
		exit(1);
	}
	if (gcfg->bind_threads_flag) {
		bind_thread(pthread_self(), bind_offset);
	}
	for (i=0; i < gcfg->writer_count + 1; i++) {
		if (i == gcfg->writer_count) {
			worker = &gcfg->translator;
			memset(worker, 0 ,sizeof(struct sworker));
			snprintf(name, name_len, "translator");
			worker->type = TRANSLATOR;
			cpu_num = bind_offset + 1;
		} else {
			worker = &gcfg->writers[i];
			snprintf(name, name_len, "writer_%d", i);
			worker->type = WRITER;
			cpu_num = bind_offset + i + 2;	//first two assigned to reader and translator
		}
		if (pthread_cond_init(&worker->has_work, 0) ||
			pthread_mutex_init(&worker->work_chain.pmtx, 0) ||
			pthread_create(&worker->thread, 0, worker_loop, worker))
		{
			slog(LOG_CRIT, "Error: unable to init %s thread: %s", name, strerror(errno));
			exit(1);
		}
		pthread_set_name_np(worker->thread, name);

		if (gcfg->bind_threads_flag)
			bind_thread(worker->thread, cpu_num);
		}
}

static inline void flush_pkt(struct pkt *p, struct iovec *iov){

	iov[0].iov_base = &p->new_header;
	iov[0].iov_len = p->new_header_len;
	iov[1].iov_base = p->data;
	iov[1].iov_len = p->data_len;

	if (writev(gcfg->tun_fd, iov, 2) < 0) {
		slog(LOG_WARNING, "error writing packet to tun "
			"device: %s\n", strerror(errno));
	}
}

static inline void handle_pkt(struct sbuf *sb)
{
		struct tun_pi *pi = (struct tun_pi *)sb->recv_buf;
		struct pkt *p = &sb->pbuf;

		switch (TUN_GET_PROTO(pi)) {
		case ETH_P_IP:
			handle_ip4(p);
			break;

		case ETH_P_IPV6:
			handle_ip6(p);
			break;

		default:
			slog(LOG_WARNING, "Dropping unknown proto %04x from "
							"tun device\n", ntohs(pi->proto));
			break;
		}
}

void *worker_loop(void *arg)
{
	struct sbuf *sb, *ib;
	struct iovec iov[2];
	uint i;
	struct sworker *self = (struct sworker *) arg;
	struct sbuf_chain *chain = &self->work_chain;

	do {
		pthread_mutex_lock(&chain->pmtx);

		while (!chain->head) {
			pthread_cond_wait(&self->has_work, &chain->pmtx);
		}
		__grab_sbuf_chain(&sb, chain);
		pthread_mutex_unlock(&chain->pmtx);

		if (sb == NULL)
			continue;

		ib = sb;
		switch(self->type) {	
		case TRANSLATOR:
			WALK_CHAIN(ib,
				handle_pkt(ib);			//translate pkt, if local-destined
										// fragmented or an icmp-error write it here
			)
			enq_chain_to_flush(sb,ib);

			if (gcfg->cache_size &&
				(gcfg->last_cache_maint + CACHE_CHECK_INTERVAL < now ||
				gcfg->last_cache_maint > now)) {

				addrmap_maint();
				gcfg->last_cache_maint = now;
			}

			if (gcfg->dynamic_pool &&
						(gcfg->last_dynamic_maint +
						POOL_CHECK_INTERVAL < now ||
						gcfg->last_dynamic_maint > now)) {

				dynamic_maint(gcfg->dynamic_pool, 0);
				gcfg->last_dynamic_maint = now;
			}
			break;

		case WRITER:
			i = 0;
			WALK_CHAIN(ib,
				if(ib->pbuf.flush_flag) { flush_pkt(&ib->pbuf, iov); } //write translated
				i++;
			)
			ret_free_chain(sb, ib, i);
			break;
		}
		
	} while(1);
} 

void thread_read_from_tun(void) 
{
	struct buf_queue *bq;
	struct sbuf *bi, *bl, *chain, *free_tail;
	uint chain_size, read_count;
	int ret;
	struct pkt *p;

	bq = gcfg->bq;
	chain = NULL;

	grab_free_chain(&chain, &free_tail, &chain_size);
	if (!chain) {
		slog(LOG_ERR, "No free bufs probably will drop\n");
		return;
	}

	bl = bi = chain;
	read_count = 0;

	while (bi != NULL &&
		((ret = read(gcfg->tun_fd, bi->recv_buf, gcfg->recv_buf_size))))
	{
		if (ret < 0) {
			if (errno == EAGAIN)
				break;
			slog(LOG_ERR, "received error when reading from tun "
					"device: %s\n", strerror(errno));
			continue;
		}
		if (ret < sizeof(struct tun_pi)) {
			slog(LOG_WARNING, "short read from tun device "
					"(%d bytes)\n", ret);
			continue;
		}
		if (ret == gcfg->recv_buf_size) {
			slog(LOG_WARNING, "dropping oversized packet\n");
			continue;
		}
		p = &bi->pbuf;
		memset(p, 0, sizeof(struct pkt));
			p->data = bi->recv_buf + sizeof(struct tun_pi);
			p->data_len = ret - sizeof(struct tun_pi);
		
		read_count++;
		bl = bi;
		bi = bi->next;
	}

	if (read_count) {
		enq_chain_to_translate(chain, bl);
	}
	if (bi != NULL) {
		ret_free_chain(bi, free_tail, (chain_size - read_count));
	}
	

	return; 
}
