#ifndef NET_IRQ_H
#define NET_IRQ_H

#include <signal.h>

#define IRQ_BASE		(SIGRTMIN + 1)
#define INTR_IRQ_SOFTIRQ	SIGUSR1
#define INTR_IRQ_EVENT		SIGUSR2

#define IRQ_NAM_SZ		16

struct irq_entry {
	struct irq_entry *next;
	unsigned int irq;
	int (*handler) (unsigned int irq, void *dev);
	unsigned int flags;
	char name[IRQ_NAM_SZ];
	void *dev;
};

extern int
irq_register(unsigned int irq, int (*handler)(unsigned int irq, void *dev), unsigned int flags, const char *name, void *dev);

extern int
irq_init(void);

extern int
irq_run(void);

extern void
irq_shutdown(void);

extern int
irq_raise(int irq);

struct sched_ctx {
    pthread_cond_t cond;
    int interrupted;
    int wc; /* wait count */
};

#define SCHED_CTX_INITIALIZER {PTHREAD_COND_INITIALIZER, 0, 0}

extern int
sched_ctx_init(struct sched_ctx *ctx);

extern int
sched_ctx_destroy(struct sched_ctx *ctx);

extern int
sched_sleep(struct sched_ctx *ctx, pthread_mutex_t *mutex, const struct timespec *abstime);

extern int
sched_wakeup(struct sched_ctx *ctx);

extern int
sched_interrupt(struct sched_ctx *ctx);

#endif
