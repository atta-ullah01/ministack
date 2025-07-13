#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "net_dev.h"
#include "net_irq.h"
#include "utils.h"

static struct irq_entry *irqs;
static sigset_t sigmask;

static pthread_t tid;
static pthread_barrier_t barrier;

int
irq_register(unsigned int irq, int (*handler)(unsigned int irq, void *dev), unsigned int flags, const char *name, void *dev)
{
	struct irq_entry *ir;
	for (ir = irqs; ir; ir = ir->next) {
		if (ir->irq == irq) {
			if ((ir->flags & NET_IRQ_SHARED) && (flags & NET_IRQ_SHARED)) {
				log_error("conflicts with registered irq=%s", ir->name);
				return -1;
			}
		}
	}
	ir = malloc(sizeof(*ir));
	if (!ir) {
		log_error("irq_register: %s", strerror(errno));
		return -1;
	}
	ir->irq = irq;
	ir->handler = handler;
	ir->flags = flags;
	strncpy(ir->name, name, IRQ_NAM_SZ - 1);
	ir->name[IRQ_NAM_SZ - 1] = '\0';
	ir->dev = dev;

	ir->next = irqs;
	irqs = ir;
	sigaddset(&sigmask, ir->irq);
	log_debug("registered: irq=%u, name=%s", ir->irq, ir->name);
	return 0;
}

int
irq_init(void)
{
	sigemptyset(&sigmask);
	sigaddset(&sigmask, SIGHUP);
	sigaddset(&sigmask, SIGUSR1);
	sigaddset(&sigmask, SIGALRM);
	tid = pthread_self();
	pthread_barrier_init(&barrier, NULL, 2);
	return 0;
}

static int
intr_timer_setup(struct itimerspec *interval)
{
	timer_t id;

	if (timer_create(CLOCK_REALTIME, NULL, &id) == -1) {
		log_error("timer_create: %s", strerror(errno));
		return -1;
	}
	if (timer_settime(id, 0, interval, NULL) == -1) {
		log_error("timer_settime: %s", strerror(errno));
		return -1;
	}
	return 0;

}

static void *
irq_routine(void *arg)
{
	const struct timespec ts = {0, 1000000}; /* 1ms */
	struct itimerspec interval = {ts, ts};

	short terminate = 0;
	pthread_barrier_wait(&barrier);
	if (intr_timer_setup(&interval) == -1) {
		log_error("intr_timer_setup() failure");
		return NULL;
	}
	while (!terminate) {
		int sig;
		sigwait(&sigmask, &sig);
		switch (sig) {
			case SIGHUP:
				terminate = 1;
				break;
			case SIGUSR1:
				net_protocol_handler();
				break;
			case SIGALRM:
				net_timer_handler();
				break;

			default:
				for (struct irq_entry *en = irqs; en; en = en->next) {
					if ((unsigned int)sig == en->irq) {
						log_debug("irq=%u, name=%s", en->irq, en->name);
						en->handler(en->irq, en->dev);
					}
				}
				break;
		}
	}
	log_debug("terminated");
	return NULL;
}

int
irq_run(void)
{
	if (pthread_sigmask(SIG_BLOCK, &sigmask, NULL) != 0) {
		log_error("pthread_sigmask: %s", strerror(errno));
		return -1;
	}
	if (pthread_create(&tid, NULL, irq_routine, NULL) != 0) {
		log_error("pthread_create: %s", strerror(errno));
		return -1;
	}
	pthread_barrier_wait(&barrier);
	return 0;
}

void
irq_shutdown(void)
{
	if (pthread_equal(tid, pthread_self()) != 0)
		return;
	pthread_kill(tid, SIGHUP);
	pthread_join(tid, NULL);
}

int
irq_raise(int irq)
{
	return pthread_kill(tid, irq);
}

int
irq_soft_raise(void)
{
	return pthread_kill(tid, SIGUSR1);
}
