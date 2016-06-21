/*
 * twemproxy - A fast and lightweight proxy for memcached protocol.
 * Copyright (C) 2011 Twitter, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdlib.h>

#include <nc_core.h>

/*
 * 创建一个数组，数组元素大小为 size，数组可以容纳的元素个数为 n
 */
struct array *
array_create(uint32_t n, size_t size)
{
    struct array *a;

    ASSERT(n != 0 && size != 0);

    a = nc_alloc(sizeof(*a));
    if (a == NULL) {
        return NULL;
    }

    a->elem = nc_alloc(n * size);
    if (a->elem == NULL) {
        nc_free(a);
        return NULL;
    }

    a->nelem = 0;
    a->size = size;
    a->nalloc = n;

    return a;
}

/*
 * 销毁一个数组
 */
void
array_destroy(struct array *a)
{
    array_deinit(a);
    nc_free(a);
}

/*
 * 初始化一个数组，数组元素大小为 size，元素个数为 n
 */
rstatus_t
array_init(struct array *a, uint32_t n, size_t size)
{
    ASSERT(n != 0 && size != 0);

    a->elem = nc_alloc(n * size);
    if (a->elem == NULL) {
        return NC_ENOMEM;
    }

    a->nelem = 0;
    a->size = size;
    a->nalloc = n;

    return NC_OK;
}

/*
 * 释放一个数组
 */
void
array_deinit(struct array *a)
{
    ASSERT(a->nelem == 0);

    if (a->elem != NULL) {
        nc_free(a->elem);
    }
}

/*
 * 返回指定元素 elem 的下标
 */
uint32_t
array_idx(struct array *a, void *elem)
{
    uint8_t *p, *q;
    uint32_t off, idx;

    ASSERT(elem >= a->elem);

    p = a->elem;
    q = elem;
    off = (uint32_t)(q - p);

    ASSERT(off % (uint32_t)a->size == 0);

    idx = off / (uint32_t)a->size;

    return idx;
}

/*
 * push一个数据至数组中，实际为尾部数据
 * 此处只返回元素的地址，并不正在压入数据
 */
void *
array_push(struct array *a)
{
    void *elem, *new;
    size_t size;

    if (a->nelem == a->nalloc) {

        /* the array is full; allocate new array */
        size = a->size * a->nalloc;
        new = nc_realloc(a->elem, 2 * size);
        if (new == NULL) {
            return NULL;
        }

        a->elem = new;
        a->nalloc *= 2;
    }

    elem = (uint8_t *)a->elem + a->size * a->nelem;
    a->nelem++;

    return elem;
}

/*
 * 弹出一个元素，实际上是弹出尾部数据的地址,并将元素个数减1
 */
void *
array_pop(struct array *a)
{
    void *elem;

    ASSERT(a->nelem != 0);

    a->nelem--;
    elem = (uint8_t *)a->elem + a->size * a->nelem;

    return elem;
}

/*
 * 获取指定下标 idx 的元素
 */
void *
array_get(struct array *a, uint32_t idx)
{
    void *elem;

    ASSERT(a->nelem != 0);
    ASSERT(idx < a->nelem);

    elem = (uint8_t *)a->elem + (a->size * idx);

    return elem;
}

/*
 * 返回尾部数据
 */
void *
array_top(struct array *a)
{
    ASSERT(a->nelem != 0);

    return array_get(a, a->nelem - 1);
}

/*
 * 交换两个数组元素
 */
void
array_swap(struct array *a, struct array *b)
{
    struct array tmp;

    tmp = *a;
    *a = *b;
    *b = tmp;
}

/*
 * Sort nelem elements of the array in ascending order based on the
 * compare comparator.
 */
/*
 * 数组排序
 */
void
array_sort(struct array *a, array_compare_t compare)
{
    ASSERT(a->nelem != 0);

    qsort(a->elem, a->nelem, a->size, compare);
}

/*
 * Calls the func once for each element in the array as long as func returns
 * success. On failure short-circuits and returns the error status.
 */
/*
 * 遍历数组
 */
rstatus_t
array_each(struct array *a, array_each_t func, void *data)
{
    uint32_t i, nelem;

    ASSERT(array_n(a) != 0);
    ASSERT(func != NULL);

    for (i = 0, nelem = array_n(a); i < nelem; i++) {
        void *elem = array_get(a, i);
        rstatus_t status;

        status = func(elem, data);
        if (status != NC_OK) {
            return status;
        }
    }

    return NC_OK;
}
