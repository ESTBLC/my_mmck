#include <criterion/criterion.h>
#include <stdio.h>

#include "intrlist.h"

struct test {
    int i;
    intrlist_t list;
};

Test(intrlist, intrlist_init) {
    intrlist_t list;
    intrlist_init(&list);

    cr_assert(list.next == &list && list.prev == &list);
}

Test(intrlist, list_push) {
    struct test list;
    struct test node1;
    struct test node2;
    intrlist_init(&list.list);

    intrlist_push(&list.list, &node1.list);
    cr_assert(list.list.next == &node1.list && list.list.prev == &node1.list);
    cr_assert(node1.list.next == &list.list && node1.list.prev == &list.list);

    intrlist_push(&list.list, &node2.list);
    cr_assert(list.list.next == &node2.list && list.list.prev == &node1.list);
    cr_assert(node2.list.next == &node1.list && node2.list.prev == &list.list);
    cr_assert(node1.list.next == &list.list && node1.list.prev == &node2.list);
}

Test(intrlist, list_append) {
    struct test list;
    struct test node1;
    struct test node2;
    intrlist_init(&list.list);

    intrlist_append(&list.list, &node1.list);
    cr_assert(list.list.next == &node1.list && list.list.prev == &node1.list);
    cr_assert(node1.list.next == &list.list && node1.list.prev == &list.list);

    intrlist_append(&list.list, &node2.list);
    cr_assert(list.list.next == &node1.list && list.list.prev == &node2.list);
    cr_assert(node2.list.next == &list.list && node2.list.prev == &node1.list);
    cr_assert(node1.list.next == &node2.list && node1.list.prev == &list.list);
}

Test(intrlist, intrlist_remove) {
    struct test list;
    struct test node1;
    struct test node2;
    intrlist_init(&list.list);

    intrlist_push(&list.list, &node1.list);
    intrlist_push(&list.list, &node2.list);

    intrlist_t *rm = intrlist_remove(&node2.list);
    cr_assert(rm == &node2.list);
    cr_assert(node2.list.next == node2.list.prev);
    cr_assert(list.list.next == &node1.list && list.list.prev == &node1.list);

    rm = intrlist_remove(&node1.list);
    cr_assert(rm == &node1.list);
    cr_assert(node1.list.next == node1.list.prev);
    cr_assert(list.list.next == &list.list && list.list.prev == &list.list);

    rm = intrlist_remove(&node1.list);
    cr_assert(rm == NULL);

    rm = intrlist_remove(&list.list);
    cr_assert(rm == NULL);
}

Test(intrlist, intrlist_pop) {
    struct test list;
    struct test node1;
    struct test node2;
    intrlist_init(&list.list);

    intrlist_push(&list.list, &node1.list);
    intrlist_push(&list.list, &node2.list);

    intrlist_t *rm = intrlist_pop(&list.list);
    cr_assert(rm == &node2.list);

    rm = intrlist_pop(&list.list);
    cr_assert(rm == &node1.list);
}

Test(intrlist, intrlist_strip) {
    struct test list;
    struct test node1;
    struct test node2;
    intrlist_init(&list.list);

    intrlist_push(&list.list, &node1.list);
    intrlist_push(&list.list, &node2.list);

    intrlist_t *rm = intrlist_strip(&list.list);
    cr_assert(rm == &node1.list);

    rm = intrlist_strip(&list.list);
    cr_assert(rm == &node2.list);
}

Test(intrlist, intrlist_entry) {
    struct test list;

    struct test *ret = intrlist_entry(&list.list, struct test, list);

    cr_assert(ret == &list);
}

Test(intrlist, intrlist_foreach) {
    struct test list;
    struct test test1;
    struct test test2;
    struct test test3;

    test1.i = 1;
    test2.i = 2;
    test3.i = 3;

    intrlist_init(&list.list);

    intrlist_push(&list.list, &test2.list);
    intrlist_push(&list.list, &test1.list);
    intrlist_append(&list.list, &test3.list);

    int index = 1;
    struct test *pos;
    intrlist_foreach(&list.list, pos, list) {
        cr_assert(pos->i == index++);
    }
}

Test(intrlist, intrlist_foreach_reverse) {
    struct test list;
    struct test test1;
    struct test test2;
    struct test test3;

    test1.i = 1;
    test2.i = 2;
    test3.i = 3;

    intrlist_init(&list.list);

    intrlist_push(&list.list, &test2.list);
    intrlist_push(&list.list, &test1.list);
    intrlist_append(&list.list, &test3.list);

    int index = 3;
    struct test *pos;
    intrlist_foreach_reverse(&list.list, pos, list) {
        cr_assert(pos->i == index--);
    }
}
