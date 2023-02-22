#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define ISR_HOME "ISR_HOME"


int main(int argc, char **argv, char **envp)
{
	int r, esize, i;
	char **e, **new_envp, *isr_home, *ldpath;

	if (argc < 2) {
		fprintf(stderr, "Not enough arguments\n");
		return -1;
	}

	/* Find out what is the size of the environment array, and look for
	 * ISR_HOME */
	isr_home = NULL;
	for (e = envp, esize=0; *e != NULL; e++, esize++) {
		if (strncmp(*e, ISR_HOME, strlen(ISR_HOME)) == 0) {
			isr_home = *e + strlen(ISR_HOME);
			if (*isr_home != '\0')
				isr_home++;
			else
				isr_home = NULL;
		}
	}
	if (!isr_home) {
		fprintf(stderr, "ISR_HOME not defined!\n");
		return -1;
	}

	//printf("ISR_HOME=%s\n", isr_home);
	ldpath = malloc(strlen(isr_home) + 64);
	if (!ldpath) {
		fprintf(stderr, "Not enough memory\n");
		return -1;
	}

	/* If you update this, make sure string still fits in ldpath, which was
	 * allocated above */
	sprintf(ldpath, "LD_LIBRARY_PATH=%s/encrypted_lib", isr_home);
	//printf("%s\n", ldpath);

	/* Allocate new enviroment array, and add ldpath */
	new_envp = malloc((esize + 2) * sizeof(char **));
	for (i = 0; i < esize; i++) {
		new_envp[i] = envp[i];
		//printf("envp[%d]=%s\n", i, envp[i]);
	}
	new_envp[i++] = ldpath;
	new_envp[i] = NULL;

#if 0
	for (i = 1; i < argc; i++)
		printf("argv[%d] = %s\n", i, argv[i]);
#endif

	//printf("Wrapper executing process %s\n", argv[1]);
	r = execve(argv[1], argv + 1, new_envp);
	perror("Execution failed");
	return -1;
}
