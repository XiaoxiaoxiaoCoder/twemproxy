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

#include <stdio.h>
#include <stdlib.h>

#include <sys/uio.h>

#include <nc_core.h>
#include <nc_server.h>
#include <proto/nc_proto.h>

#if (IOV_MAX > 128)
#define NC_IOV_MAX 128
#else
#define NC_IOV_MAX IOV_MAX
#endif

/*
 *            nc_message.[ch]
 *         message (struct msg)
 *            +        +            .
 *            |        |            .
 *            /        \            .
 *         Request    Response      .../ nc_mbuf.[ch]  (mesage buffers)
 *      nc_request.c  nc_response.c .../ nc_memcache.c; nc_redis.c (message parser)
 *
 * Messages in nutcracker are manipulated by a chain of processing handlers,
 * where each handler is responsible for taking the input and producing an
 * output for the next handler in the chain. This mechanism of processing
 * loosely conforms to the standard chain-of-responsibility design pattern
 *
 * At the high level, each handler takes in a message: request or response
 * and produces the message for the next handler in the chain. The input
 * for a handler is either a request or response, but never both and
 * similarly the output of an handler is either a request or response or
 * nothing.
 *
 * Each handler itself is composed of two processing units:
 *
 * 1). filter: manipulates output produced by the handler, usually based
 *     on a policy. If needed, multiple filters can be hooked into each
 *     location.
 * 2). forwarder: chooses one of the backend servers to send the request
 *     to, usually based on the configured distribution and key hasher.
 *
 * Handlers are registered either with Client or Server or Proxy
 * connections. A Proxy connection only has a read handler as it is only
 * responsible for accepting new connections from client. Read handler
 * (conn_recv_t) registered with client is responsible for reading requests,
 * while that registered with server is responsible for reading responses.
 * Write handler (conn_send_t) registered with client is responsible for
 * writing response, while that registered with server is responsible for
 * writing requests.
 *
 * Note that in the above discussion, the terminology send is used
 * synonymously with write or OUT event. Similarly recv is used synonymously
 * with read or IN event
 *
 *             Client+             Proxy           Server+
 *                              (nutcracker)
 *                                   .
 *       msg_recv {read event}       .       msg_recv {read event}
 *         +                         .                         +
 *         |                         .                         |
 *         \                         .                         /
 *         req_recv_next             .             rsp_recv_next
 *           +                       .                       +
 *           |                       .                       |       Rsp
 *           req_recv_done           .           rsp_recv_done      <===
 *             +                     .                     +
 *             |                     .                     |
 *    Req      \                     .                     /
 *    ===>     req_filter*           .           *rsp_filter
 *               +                   .                   +
 *               |                   .                   |
 *               \                   .                   /
 *               req_forward-//  (a) . (c)  \\-rsp_forward
 *                                   .
 *                                   .
 *       msg_send {write event}      .      msg_send {write event}
 *         +                         .                         +
 *         |                         .                         |
 *    Rsp' \                         .                         /     Req'
 *   <===  rsp_send_next             .             req_send_next     ===>
 *           +                       .                       +
 *           |                       .                       |
 *           \                       .                       /
 *           rsp_send_done-//    (d) . (b)    //-req_send_done
 *
 *
 * (a) -> (b) -> (c) -> (d) is the normal flow of transaction consisting
 * of a single request response, where (a) and (b) handle request from
 * client, while (c) and (d) handle the corresponding response from the
 * server.
 */

/* 消息id计数 */
static uint64_t msg_id;             /* message id counter */
static uint64_t frag_id;            /* fragment id counter */
static uint32_t nfree_msgq;         /* # free msg q */
static struct   msg_tqh free_msgq;  /* free msg q */
static struct   rbtree tmo_rbt;     /* timeout rbtree */
static struct   rbnode tmo_rbs;     /* timeout rbtree sentinel */

#define DEFINE_ACTION(_name) string(#_name),
static struct string msg_type_strings[] = {
    MSG_TYPE_CODEC( DEFINE_ACTION )
    null_string
};
#undef DEFINE_ACTION

/*
 * 从红黑色节点中获取消息对象
 */
static struct msg *
msg_from_rbe(struct rbnode *node)
{
    struct msg *msg;
    int offset;

    offset = offsetof(struct msg, tmo_rbe);
    msg = (struct msg *)((char *)node - offset);

    return msg;
}

/*
 * 获取红黑树中值最小的节点
 */
struct msg *
msg_tmo_min(void)
{
    struct rbnode *node;

    node = rbtree_min(&tmo_rbt);
    if (node == NULL) {
        return NULL;
    }

    return msg_from_rbe(node);
}

/*
 * 将消息节点插入红黑树
 */
void
msg_tmo_insert(struct msg *msg, struct conn *conn)
{
    struct rbnode *node;
    int timeout;

    ASSERT(msg->request);
    ASSERT(!msg->quit && !msg->noreply);

    timeout = server_timeout(conn);
    if (timeout <= 0) {
        return;
    }

    node = &msg->tmo_rbe;
    node->key = nc_msec_now() + timeout;
    node->data = conn;

    rbtree_insert(&tmo_rbt, node);

    log_debug(LOG_VERB, "insert msg %"PRIu64" into tmo rbt with expiry of "
              "%d msec", msg->id, timeout);
}

/*
 * 从红黑树中删除指定的消息节点
 */
void
msg_tmo_delete(struct msg *msg)
{
    struct rbnode *node;

    node = &msg->tmo_rbe;

    /* already deleted */

    if (node->data == NULL) {
        return;
    }

    rbtree_delete(&tmo_rbt, node);

    log_debug(LOG_VERB, "delete msg %"PRIu64" from tmo rbt", msg->id);
}

/*
 * 获取一个空闲的消息
 */
static struct msg *
_msg_get(void)
{
    struct msg *msg;

    if (!TAILQ_EMPTY(&free_msgq)) {
        ASSERT(nfree_msgq > 0);

        msg = TAILQ_FIRST(&free_msgq);
        nfree_msgq--;
        TAILQ_REMOVE(&free_msgq, msg, m_tqe);
        goto done;
    }

    msg = nc_alloc(sizeof(*msg));
    if (msg == NULL) {
        return NULL;
    }

done:
    /* c_tqe, s_tqe, and m_tqe are left uninitialized */
    msg->id     = ++msg_id;
    msg->peer   = NULL;
    msg->owner  = NULL;

    rbtree_node_init(&msg->tmo_rbe);

    STAILQ_INIT(&msg->mhdr);
    msg->mlen       = 0;
    msg->start_ts   = 0;

    msg->state      = 0;
    msg->pos        = NULL;
    msg->token      = NULL;

    msg->parser     = NULL;
    msg->add_auth   = NULL;
    msg->result     = MSG_PARSE_OK;

    msg->fragment   = NULL;
    msg->reply      = NULL;
    msg->pre_coalesce  = NULL;
    msg->post_coalesce = NULL;

    msg->type = MSG_UNKNOWN;

    msg->keys = array_create(1, sizeof(struct keypos));
    if (msg->keys == NULL) {
        nc_free(msg);
        return NULL;
    }

    msg->vlen   = 0;
    msg->end    = NULL;

    msg->frag_owner = NULL;
    msg->frag_seq   = NULL;
    msg->nfrag      = 0;
    msg->nfrag_done = 0;
    msg->frag_id    = 0;

    msg->narg_start = NULL;
    msg->narg_end   = NULL;
    msg->narg       = 0;
    msg->rnarg      = 0;
    msg->rlen       = 0;
    msg->integer    = 0;

    msg->err        = 0;
    msg->error      = 0;
    msg->ferror     = 0;
    msg->request    = 0;
    msg->quit       = 0;
    msg->noreply    = 0;
    msg->noforward  = 0;
    msg->done       = 0;
    msg->fdone      = 0;
    msg->swallow    = 0;
    msg->redis      = 0;

    return msg;
}

/*
 * 获取一个 msg 对象,并指明消息是否为请求，请求类型是为redis或者mc
 */
struct msg *
msg_get(struct conn *conn, bool request, bool redis)
{
    struct msg *msg;

    msg = _msg_get();
    if (msg == NULL) {
        return NULL;
    }

    msg->owner      = conn;
    msg->request    = request ? 1 : 0;
    msg->redis      = redis ? 1 : 0;

    /* redis协议 */
    if (redis) {
        if (request) {
            msg->parser = redis_parse_req;
        } else {
            msg->parser = redis_parse_rsp;
        }
        msg->add_auth       = redis_add_auth;
        msg->fragment       = redis_fragment;
        msg->reply          = redis_reply;
        msg->failure        = redis_failure;
        msg->pre_coalesce   = redis_pre_coalesce;
        msg->post_coalesce  = redis_post_coalesce;
    } else {                // MC 协议
        if (request) {
            msg->parser = memcache_parse_req;
        } else {
            msg->parser = memcache_parse_rsp;
        }
        msg->add_auth       = memcache_add_auth;
        msg->fragment       = memcache_fragment;
        msg->failure        = memcache_failure;
        msg->pre_coalesce   = memcache_pre_coalesce;
        msg->post_coalesce  = memcache_post_coalesce;
    }

    if (log_loggable(LOG_NOTICE) != 0) {
        msg->start_ts = nc_usec_now();
    }

    log_debug(LOG_VVERB, "get msg %p id %"PRIu64" request %d owner sd %d",
              msg, msg->id, msg->request, conn->sd);

    return msg;
}

/*
 * 根据错误码获取错误信息
 */
struct msg *
msg_get_error(bool redis, err_t err)
{
    struct msg *msg;
    struct mbuf *mbuf;
    int n;
    char *errstr = err ? strerror(err) : "unknown";
    char *protstr = redis ? "-ERR" : "SERVER_ERROR";

    msg = _msg_get();
    if (msg == NULL) {
        return NULL;
    }

    msg->state = 0;
    msg->type = MSG_RSP_MC_SERVER_ERROR;

    mbuf = mbuf_get();
    if (mbuf == NULL) {
        msg_put(msg);
        return NULL;
    }
    mbuf_insert(&msg->mhdr, mbuf);

    n = nc_scnprintf(mbuf->last, mbuf_size(mbuf), "%s %s"CRLF, protstr, errstr);
    mbuf->last += n;
    msg->mlen = (uint32_t)n;

    log_debug(LOG_VVERB, "get msg %p id %"PRIu64" len %"PRIu32" error '%s'",
              msg, msg->id, msg->mlen, errstr);

    return msg;
}

/*
 * 释放指定的消息结构体
 */
static void
msg_free(struct msg *msg)
{
    ASSERT(STAILQ_EMPTY(&msg->mhdr));

    log_debug(LOG_VVERB, "free msg %p id %"PRIu64"", msg, msg->id);
    nc_free(msg);
}

/*
 * 将指定的消息放入空闲消息列表中
 */
void
msg_put(struct msg *msg)
{
    log_debug(LOG_VVERB, "put msg %p id %"PRIu64"", msg, msg->id);

    while (!STAILQ_EMPTY(&msg->mhdr)) {
        struct mbuf *mbuf = STAILQ_FIRST(&msg->mhdr);
        mbuf_remove(&msg->mhdr, mbuf);
        mbuf_put(mbuf);
    }
    /* 释放分片数组 */
    if (msg->frag_seq) {
        nc_free(msg->frag_seq);
        msg->frag_seq = NULL;
    }

    /* 释放key数组 */
    if (msg->keys) {
        msg->keys->nelem = 0; /* a hack here */
        array_destroy(msg->keys);
        msg->keys = NULL;
    }

    nfree_msgq++;
    TAILQ_INSERT_HEAD(&free_msgq, msg, m_tqe);
}

/*
 * 打印出 msg 消息
 */
void
msg_dump(struct msg *msg, int level)
{
    struct mbuf *mbuf;

    if (log_loggable(level) == 0) {
        return;
    }

    loga("msg dump id %"PRIu64" request %d len %"PRIu32" type %d done %d "
         "error %d (err %d)", msg->id, msg->request, msg->mlen, msg->type,
         msg->done, msg->error, msg->err);

    STAILQ_FOREACH(mbuf, &msg->mhdr, next) {
        uint8_t *p, *q;
        long int len;

        p = mbuf->start;
        q = mbuf->last;
        len = q - p;

        loga_hexdump(p, len, "mbuf [%p] with %ld bytes of data", p, len);
    }
}

/*
 * 初始化 msg 信息
 */
void
msg_init(void)
{
    log_debug(LOG_DEBUG, "msg size %d", sizeof(struct msg));
    msg_id      = 0;
    frag_id     = 0;
    nfree_msgq  = 0;
    TAILQ_INIT(&free_msgq);
    rbtree_init(&tmo_rbt, &tmo_rbs);
}

/*
 * 销毁 msg 信息
 */
void
msg_deinit(void)
{
    struct msg *msg, *nmsg;

    for (msg = TAILQ_FIRST(&free_msgq); msg != NULL;
         msg = nmsg, nfree_msgq--) {
        ASSERT(nfree_msgq > 0);
        nmsg = TAILQ_NEXT(msg, m_tqe);
        msg_free(msg);
    }
    ASSERT(nfree_msgq == 0);
}

/*
 * 返回指定类型的名称
 */
struct string *
msg_type_string(msg_type_t type)
{
    return &msg_type_strings[type];
}

/*
 * 检测 msg 中数据是否为空
 */
bool
msg_empty(struct msg *msg)
{
    return msg->mlen == 0 ? true : false;
}

/*
 * 根据 key 返回后端 svr 的 id
 */
uint32_t
msg_backend_idx(struct msg *msg, uint8_t *key, uint32_t keylen)
{
    struct conn *conn = msg->owner;
    struct server_pool *pool = conn->owner;

    return server_pool_idx(pool, key, keylen);
}

/*
 * 确保 msg 中的 buf 可以存储下长度为 len 的数据
 * 如果 mbuf 空闲空间不够则获取一个新的 mbuf 并返回
 */
struct mbuf *
msg_ensure_mbuf(struct msg *msg, size_t len)
{
    struct mbuf *mbuf;

    if (STAILQ_EMPTY(&msg->mhdr) ||
        mbuf_size(STAILQ_LAST(&msg->mhdr, mbuf, next)) < len) {
        mbuf = mbuf_get();
        if (mbuf == NULL) {
            return NULL;
        }
        mbuf_insert(&msg->mhdr, mbuf);
    } else {
        mbuf = STAILQ_LAST(&msg->mhdr, mbuf, next);
    }

    return mbuf;
}

/*
 * Append n bytes of data, with n <= mbuf_size(mbuf)
 * into mbuf
 */
/*
 * 追加长度为 n 的数据至 msg 中
 */
rstatus_t
msg_append(struct msg *msg, uint8_t *pos, size_t n)
{
    struct mbuf *mbuf;

    ASSERT(n <= mbuf_data_size());

    mbuf = msg_ensure_mbuf(msg, n);
    if (mbuf == NULL) {
        return NC_ENOMEM;
    }

    ASSERT(n <= mbuf_size(mbuf));

    mbuf_copy(mbuf, pos, n);
    msg->mlen += (uint32_t)n;

    return NC_OK;
}

/*
 * Prepend n bytes of data, with n <= mbuf_size(mbuf)
 * into mbuf
 */
/*
 * 在 msg 头部添加长度为 n 的数据
 */
rstatus_t
msg_prepend(struct msg *msg, uint8_t *pos, size_t n)
{
    struct mbuf *mbuf;

    mbuf = mbuf_get();
    if (mbuf == NULL) {
        return NC_ENOMEM;
    }

    ASSERT(n <= mbuf_size(mbuf));

    mbuf_copy(mbuf, pos, n);
    msg->mlen += (uint32_t)n;

    STAILQ_INSERT_HEAD(&msg->mhdr, mbuf, next);

    return NC_OK;
}

/*
 * Prepend a formatted string into msg. Returns an error if the formatted
 * string does not fit in a single mbuf.
 */
/*
 * 在 msg 头部添加格式化的数据
 */
rstatus_t
msg_prepend_format(struct msg *msg, const char *fmt, ...)
{
    struct mbuf *mbuf;
    int n;
    uint32_t size;
    va_list args;

    mbuf = mbuf_get();
    if (mbuf == NULL) {
        return NC_ENOMEM;
    }

    size = mbuf_size(mbuf);

    va_start(args, fmt);
    n = nc_vsnprintf(mbuf->last, size, fmt, args);
    va_end(args);
    if (n <= 0 || n >= (int)size) {
        return NC_ERROR;
    }

    mbuf->last += n;
    msg->mlen += (uint32_t)n;
    STAILQ_INSERT_HEAD(&msg->mhdr, mbuf, next);

    return NC_OK;
}

/*
 * 返回分片 id
 */
inline uint64_t
msg_gen_frag_id(void)
{
    return ++frag_id;
}

/*
 * 数据已经解析完毕，处理已解析的数据的 msg
 */
static rstatus_t
msg_parsed(struct context *ctx, struct conn *conn, struct msg *msg)
{
    struct msg *nmsg;
    struct mbuf *mbuf, *nbuf;

    mbuf = STAILQ_LAST(&msg->mhdr, mbuf, next);
    /* 没有更多数据了，即说明当前msg只有一条完整的协议数据，不需要进行切割 */
    if (msg->pos == mbuf->last) {
        /* no more data to parse */
        conn->recv_done(ctx, conn, msg, NULL);
        return NC_OK;
    }

    /*
     * Input mbuf has un-parsed data. Split mbuf of the current message msg
     * into (mbuf, nbuf), where mbuf is the portion of the message that has
     * been parsed and nbuf is the portion of the message that is un-parsed.
     * Parse nbuf as a new message nmsg in the next iteration.
     */
    /*
     * 切割数据，将完整的协议数据保存在当前 msg 中
     * 下一条协议的数据用一个新的 mbuf 存储并保存至一个新的 msg 
     */
    nbuf = mbuf_split(&msg->mhdr, msg->pos, NULL, NULL);
    if (nbuf == NULL) {
        return NC_ENOMEM;
    }

    nmsg = msg_get(msg->owner, msg->request, conn->redis);
    if (nmsg == NULL) {
        mbuf_put(nbuf);
        return NC_ENOMEM;
    }
    mbuf_insert(&nmsg->mhdr, nbuf);
    nmsg->pos = nbuf->pos;

    /* update length of current (msg) and new message (nmsg) */
    nmsg->mlen = mbuf_length(nbuf);
    msg->mlen -= nmsg->mlen;

    conn->recv_done(ctx, conn, msg, nmsg);

    return NC_OK;
}

/*
 * msg 中的数据不完整，且解析token过程中，mbuf已经没有空闲空间接收数据
 * 此时需要用一个新的 mbuf 存储解析过程中的 token 并继续接收数据
 */
static rstatus_t
msg_repair(struct context *ctx, struct conn *conn, struct msg *msg)
{
    struct mbuf *nbuf;

    nbuf = mbuf_split(&msg->mhdr, msg->pos, NULL, NULL);
    if (nbuf == NULL) {
        return NC_ENOMEM;
    }
    mbuf_insert(&msg->mhdr, nbuf);
    msg->pos = nbuf->pos;

    return NC_OK;
}

/*
 * 解析协议数据
 */
static rstatus_t
msg_parse(struct context *ctx, struct conn *conn, struct msg *msg)
{
    rstatus_t status;

    if (msg_empty(msg)) {
        /* no data to parse */
        conn->recv_done(ctx, conn, msg, NULL);
        return NC_OK;
    }

    msg->parser(msg);

    switch (msg->result) {
    case MSG_PARSE_OK:                              // 协议数据完整
        status = msg_parsed(ctx, conn, msg);
        break;

    case MSG_PARSE_REPAIR:                          // 协议数据不完整，需要继续接收
        status = msg_repair(ctx, conn, msg);
        break;

    case MSG_PARSE_AGAIN:
        status = NC_OK;
        break;

    default:
        status = NC_ERROR;
        conn->err = errno;
        break;
    }

    return conn->err != 0 ? NC_ERROR : status;
}

/*
 * 接收数据链
 */
static rstatus_t
msg_recv_chain(struct context *ctx, struct conn *conn, struct msg *msg)
{
    rstatus_t status;
    struct msg *nmsg;
    struct mbuf *mbuf;
    size_t msize;
    ssize_t n;

    /* 当前 msg 中的 mbuf 为空或者数据已满则分配一个新的 mbuf */
    mbuf = STAILQ_LAST(&msg->mhdr, mbuf, next);
    if (mbuf == NULL || mbuf_full(mbuf)) {
        mbuf = mbuf_get();
        if (mbuf == NULL) {
            return NC_ENOMEM;
        }
        mbuf_insert(&msg->mhdr, mbuf);
        msg->pos = mbuf->pos;
    }
    ASSERT(mbuf->end - mbuf->last > 0);

    msize = mbuf_size(mbuf);

    n = conn_recv(conn, mbuf->last, msize);
    if (n < 0) {
        if (n == NC_EAGAIN) {
            return NC_OK;
        }
        return NC_ERROR;
    }

    ASSERT((mbuf->last + n) <= mbuf->end);
    mbuf->last += n;
    msg->mlen += (uint32_t)n;

    for (;;) {
        status = msg_parse(ctx, conn, msg);
        if (status != NC_OK) {
            return status;
        }

        /* get next message to parse */
        /* 当前接收的数据包含多条完整的协议，则需要继续解析下一条数据 */
        nmsg = conn->recv_next(ctx, conn, false);
        if (nmsg == NULL || nmsg == msg) {
            /* no more data to parse */
            break;
        }

        msg = nmsg;
    }

    return NC_OK;
}

/*
 * 接收数据的回调
 * 根据不同类型的 conn 的不同接收接口来接收数据
 */
rstatus_t
msg_recv(struct context *ctx, struct conn *conn)
{
    rstatus_t status;
    struct msg *msg;

    ASSERT(conn->recv_active);

    conn->recv_ready = 1;
    do {
        msg = conn->recv_next(ctx, conn, true);
        if (msg == NULL) {
            return NC_OK;
        }

        status = msg_recv_chain(ctx, conn, msg);
        if (status != NC_OK) {
            return status;
        }
    } while (conn->recv_ready);

    return NC_OK;
}

/*
 * 发送数据
 * conn 为与后端svr的链接， msg 为需要发送的数据
 */
static rstatus_t
msg_send_chain(struct context *ctx, struct conn *conn, struct msg *msg)
{
    struct msg_tqh send_msgq;            /* send msg q */
    struct msg *nmsg;                    /* next msg */
    struct mbuf *mbuf, *nbuf;            /* current and next mbuf */
    size_t mlen;                         /* current mbuf data length */
    struct iovec *ciov, iov[NC_IOV_MAX]; /* current iovec */
    struct array sendv;                  /* send iovec */
    size_t nsend, nsent;                 /* bytes to send; bytes sent */
    size_t limit;                        /* bytes to send limit */
    ssize_t n;                           /* bytes sent by sendv */

    TAILQ_INIT(&send_msgq);

    array_set(&sendv, iov, sizeof(iov[0]), NC_IOV_MAX);

    /* preprocess - build iovec */

    nsend = 0;
    /*
     * readv() and writev() returns EINVAL if the sum of the iov_len values
     * overflows an ssize_t value Or, the vector count iovcnt is less than
     * zero or greater than the permitted maximum.
     */
    limit = SSIZE_MAX;

    for (;;) {
        ASSERT(conn->smsg == msg);

        TAILQ_INSERT_TAIL(&send_msgq, msg, m_tqe);

        for (mbuf = STAILQ_FIRST(&msg->mhdr);
             mbuf != NULL && array_n(&sendv) < NC_IOV_MAX && nsend < limit;
             mbuf = nbuf) {
            nbuf = STAILQ_NEXT(mbuf, next);

            if (mbuf_empty(mbuf)) {
                continue;
            }

            mlen = mbuf_length(mbuf);
            if ((nsend + mlen) > limit) {
                mlen = limit - nsend;
            }

            ciov = array_push(&sendv);
            ciov->iov_base = mbuf->pos;
            ciov->iov_len = mlen;

            nsend += mlen;
        }

        if (array_n(&sendv) >= NC_IOV_MAX || nsend >= limit) {
            break;
        }

        msg = conn->send_next(ctx, conn);
        if (msg == NULL) {
            break;
        }
    }

    /*
     * (nsend == 0) is possible in redis multi-del
     * see PR: https://github.com/twitter/twemproxy/pull/225
     */
    conn->smsg = NULL;
    if (!TAILQ_EMPTY(&send_msgq) && nsend != 0) {
        n = conn_sendv(conn, &sendv, nsend);
    } else {
        n = 0;
    }

    nsent = n > 0 ? (size_t)n : 0;

    /* postprocess - process sent messages in send_msgq */
    /* 处理已发送数据的 msg 中 mbuf 的数据 */
    for (msg = TAILQ_FIRST(&send_msgq); msg != NULL; msg = nmsg) {
        nmsg = TAILQ_NEXT(msg, m_tqe);

        TAILQ_REMOVE(&send_msgq, msg, m_tqe);

        if (nsent == 0) {
            if (msg->mlen == 0) {
                conn->send_done(ctx, conn, msg);
            }
            continue;
        }

        /* adjust mbufs of the sent message */
        for (mbuf = STAILQ_FIRST(&msg->mhdr); mbuf != NULL; mbuf = nbuf) {
            nbuf = STAILQ_NEXT(mbuf, next);

            if (mbuf_empty(mbuf)) {
                continue;
            }

            mlen = mbuf_length(mbuf);
            if (nsent < mlen) {
                /* mbuf was sent partially; process remaining bytes later */
                mbuf->pos += nsent;
                ASSERT(mbuf->pos < mbuf->last);
                nsent = 0;
                break;
            }

            /* mbuf was sent completely; mark it empty */
            mbuf->pos = mbuf->last;
            nsent -= mlen;
        }

        /* message has been sent completely, finalize it */
        if (mbuf == NULL) {
            conn->send_done(ctx, conn, msg);
        }
    }

    ASSERT(TAILQ_EMPTY(&send_msgq));

    if (n >= 0) {
        return NC_OK;
    }

    return (n == NC_EAGAIN) ? NC_OK : NC_ERROR;
}

/*
 * 发送数据
 * conn 为与后端的链接
 */
rstatus_t
msg_send(struct context *ctx, struct conn *conn)
{
    rstatus_t status;
    struct msg *msg;

    ASSERT(conn->send_active);

    conn->send_ready = 1;
    do {
        msg = conn->send_next(ctx, conn);
        if (msg == NULL) {
            /* nothing to send */
            return NC_OK;
        }

        status = msg_send_chain(ctx, conn, msg);
        if (status != NC_OK) {
            return status;
        }

    } while (conn->send_ready);

    return NC_OK;
}
