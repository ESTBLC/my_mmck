#ifndef HTAB_H
#define HTAB_H

#include <stddef.h>
#include <stdbool.h>

#include "../intrlist/intrlist.h"

/* An htab need an hash function given by the user */
struct bucket {
    const void *key;
    const void *elm;
    intrlist_t list;
};

struct htab {
    size_t cap;
    size_t size;
    size_t nb_elm;
    size_t (*hfunc)(const void *);
    bool (*cmpfunc)(const void *, const void *);
    struct bucket *tab;
};

typedef struct htab htab_t;

/* Create a new htab */
htab_t *htab_new(size_t (*hfunc)(const void *),
                 bool (*cmpfunc)(const void *, const void *));
/* Delete the htab */
void htab_free(htab_t *htab);

/* Add a new element in the htab */
void htab_add(htab_t *htab, const void *key, const void *elm);
/* Find a match in the htab */
void *htab_find(htab_t *htab, const void *key);
/* Remove an element of the htab */
void *htab_del(htab_t *htab, const void *rey);

#endif
