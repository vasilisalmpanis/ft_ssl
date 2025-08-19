#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
/*
 * MD% steps
 * 1. Input Padding
 * 2. Length Appending
 * 3. Buffer Initialization
 * 4. Message Processing
 * 5. Output
 */

#define USAGE_MSG "command [flags]... [file/string]...\n"

#define HELP_MSG  "\nStandard commands:\n" \
	"md5 sha256\n" \
	"\nOptions:\n" \
	"  -p	echo STDIN to STDOUT and append the checksum to STDOUT\n" \
	"  -s	quiet mode\n" \
	"  -q	reverse the format of the output\n" \
	"  -r	print the sum of the given string\n" \
	"\nExit status:\n" \
	" 0  if OK,\n" \
	" 1  if minor problems\n" \
	" 2  if serious trouble (e.g., cannot access command-line argument).\n"

void help()
{
	printf("%s", HELP_MSG);
}

void usage(char *name)
{
	printf("Usage: %s %s", name, USAGE_MSG);
	help();
}

int main(int argc, char *argv[])
{
	char *program_name = argv[0];

	if (argc == 1) {
		usage(program_name);
		exit(0);
	}
	return 0;
}
