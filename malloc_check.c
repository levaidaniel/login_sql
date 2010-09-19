#include <stdio.h>
#include <string.h>

#include "common.h"

int
malloc_check(void *p) {
	if (p == NULL) {
		printf("%s\n", strerror(ENOMEM));
		exit(EXIT_FAILURE);
	} else {
		return(EXIT_SUCCESS);
	}
} /* malloc_check() */
