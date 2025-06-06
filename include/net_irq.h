#ifndef NET_IRQ_H
#define NET_IRQ_H

#define IRQ_NAM_SZ 16

struct irq_entry {
	struct irq_entry *next;
	unsigned int irq;
	int (*handler) (unsigned int irq, void *dev);
	unsigned int flags;
	char name[IRQ_NAM_SZ];
	void *dev;
};

int
irq_register(unsigned int irq, int (*handler)(unsigned int irq, void *dev), unsigned int flags, const char *name, void *dev);

int
irq_init(void);

int
irq_run(void);

void
irq_shutdown(void);

int
irq_raise(int irq);


#endif
