#ifndef NET_IRQ_H
#define NET_IRQ_H

#include <signal.h>

#define IRQ_BASE	(SIGRTMIN + 1)
#define IRQ_NAM_SZ	16

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

extern int
irq_soft_raise(void);

#endif
