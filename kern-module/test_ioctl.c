#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#include "/home/pavletsov21/eltex/knm/common/ioctl_cmd.h"

int main() 
{
	int answer;
	struct mystruct test = {
		.repeate = 37,
		.name = "Feodor"
	};
	int dev = open("/dev/mynetmod", O_WRONLY);
	if (dev == -1)
	{
		perror("open()");
		return -1;
	}
	printf("Opening was succsessfuly!\n");

	ioctl(dev, RD_VALUE, &answer);
	printf("The answer is %d\n", answer);

	answer = 123;

	printf("The answer is %d\n", answer);

	ioctl(dev, GREETER, &test);

	close(dev);
	return 0;
}