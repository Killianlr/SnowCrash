#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

int	main(int ac, char **av)
{
	if (ac != 2)
	{
		printf("Wrong number arguments\n");
		return 1;
	}
	int file = open(av[1], O_RDONLY);
	if (file < 0)
	{
		printf("Open failed\n");
		return 1;
	}
	char buffer[1024];
	int ret = read(file, &buffer, 1024);
	if (ret <= 0)
	{
		printf("Read failed\n");
		return (1);
	}
	int	i = 0;
	while (i < ret && buffer[i] != '\n')
	{
		putchar( buffer[i] - i);
		i++;
	}
	return 0;
}