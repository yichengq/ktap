#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

static int __init funct_init(void)
{
	printk("Hello World!\n");
	return 0;
}

void funct_void()
{
}
EXPORT_SYMBOL(funct_void);

int funct_int1(unsigned char a, char b, unsigned short c, short d)
{
	return a + b + c + d;
}
EXPORT_SYMBOL(funct_int1);

long long funct_int2(unsigned int a, int b, unsigned long c, long d,
		unsigned long long e, long long f, long long g)
{
	return a + b + c + d + e + f + g;
}
EXPORT_SYMBOL(funct_int2);

void *funct_pointer1(char *a) {
	return a;
}
EXPORT_SYMBOL(funct_pointer1);

static void __exit funct_exit(void)
{
	printk("Goodbye!\n");
}

module_init(funct_init);
module_exit(funct_exit);
