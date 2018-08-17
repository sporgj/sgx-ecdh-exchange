/**
 * Copyright (c) 2018, Judicael Djoko <jbriand@cs.pitt.edu>
 *
 * This is Free Sotfware.
 */

// -------------------------- utilities -----------------------

void *
ocall_calloc(size_t size)
{
    void * ptr = calloc(1, size);
    if (ptr == NULL) {
        log_error("allocation error");
    }

    return ptr;
}

void
ocall_free(void * ptr)
{
    free(ptr);
}

void
ocall_print(char * str)
{
    printf("%s", str);
    fflush(stdout);
}
