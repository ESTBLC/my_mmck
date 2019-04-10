#include <criterion/criterion.h>

#include "htab.h"

struct tuple {
    size_t index;
    size_t val;
};

static size_t hfunc(void *key)
{
    return *(int *)key % 2;
}

static bool cmpfunc(void *key1, void *key2)
{
    return *(int *)key1 == *(int *)key2;
}

Test(htab, htab_new) {
    htab_t *htab = htab_new(hfunc, cmpfunc);

    cr_assert(htab->cap == 1);
    cr_assert(htab->size == 0);
    cr_assert(htab->nb_elm == 0);
    cr_assert(htab->hfunc);
    cr_assert(htab->cmpfunc);
    cr_assert(htab->tab);

    htab_free(htab);
}

Test(htab, htab_add) {
    htab_t *htab = htab_new(hfunc, cmpfunc);

    struct tuple t1 = {0, 1};
    struct tuple t2 = {2, 2};
    struct tuple t3 = {3, 3};

    htab_add(htab, &t1.index, &t1);
    cr_assert(htab->cap == 1);
    cr_assert(htab->size == 1);
    cr_assert(htab->nb_elm == 1);
    cr_assert(intrlist_entry(htab->tab[0].list.next, struct bucket, list)->elm == &t1);

    htab_add(htab, &t2.index, &t2);
    cr_assert(htab->cap == 2);
    cr_assert(htab->size == 1);
    cr_assert(htab->nb_elm == 2);
    cr_assert(intrlist_entry(htab->tab[0].list.next->next, struct bucket, list)->elm == &t1);

    htab_add(htab, &t3.index, &t3);
    cr_assert(htab->cap == 2);
    cr_assert(htab->size == 2);
    cr_assert(htab->nb_elm == 3);
    cr_assert(intrlist_entry(htab->tab[1].list.next, struct bucket, list)->elm == &t3);

    htab_free(htab);
}

Test(htab, htab_find) {
    htab_t *htab = htab_new(hfunc, cmpfunc);

    struct tuple t1 = {0, 1};
    struct tuple t2 = {2, 2};
    struct tuple t3 = {3, 3};

    htab_add(htab, &t1.index, &t1);
    htab_add(htab, &t2.index, &t2);
    htab_add(htab, &t3.index, &t3);

    size_t i = 0;
    struct tuple *t = htab_find(htab, &i);
    cr_assert(t->index == i);
    cr_assert(t->val == 1);

    i = 2;
    t = htab_find(htab, &i);
    cr_assert(t->index == i);
    cr_assert(t->val == 2);

    i = 3;
    t = htab_find(htab, &i);
    cr_assert(t->index == 3);
    cr_assert(t->val == 3);

    htab_free(htab);
}

Test(htab, htab_remove) {
    htab_t *htab = htab_new(hfunc, cmpfunc);

    struct tuple t1 = {0, 1};
    struct tuple t2 = {2, 2};
    struct tuple t3 = {3, 3};

    htab_add(htab, &t1.index, &t1);
    htab_add(htab, &t2.index, &t2);
    htab_add(htab, &t3.index, &t3);

    size_t i = 0;
    struct tuple *t = htab_del(htab, &i);
    cr_assert(t->index == i);
    cr_assert(t->val == 1);
    cr_assert(htab->size == 2);
    cr_assert(htab->nb_elm == 2);

    i = 2;
    t = htab_del(htab, &i);
    cr_assert(t->index == i);
    cr_assert(t->val == 2);
    cr_assert(htab->size == 1);
    cr_assert(htab->nb_elm == 1);


    i = 3;
    t = htab_del(htab, &i);
    cr_assert(t->index == 3);
    cr_assert(t->val == 3);
    cr_assert(htab->size == 0);
    cr_assert(htab->nb_elm == 0);

    htab_free(htab);
}

