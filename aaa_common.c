/*
 * Copyright(C) 2012 Ruijie Networks. All rights reserved.
 */
/*
 * aaa_common.c
 * Original Author:  zhongguirong@ruijie.com.cn, 2012-8-14
 *
 * Implementation of common functions used by aaalib and aaad.
 *
 * History
 *   v1.1    liuchenhong@ruijie.com.cn, 2013-12-23
 *           Revise for coding standard.
 */

#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
#include <rg-ham/ham.h>
#include <rg-ham/ham_rpc.h>
#include "aaa_common.h"
#include "aaa_ipc_msg.h"

#define TLV_ADD_WHOLE_LEN(len, p) (len) += (TLV_HEADER_LEN + TLV_LEN((p)))

/* record msg send fail times */
aaa_msg_stat_t g_aaa_msg_stat = {0};

/* RADIUS terminate cause string */
typedef struct {
    int term_cause_code;
    char str[RDS_ACCT_TERM_CAUSE_STRING_MAX_LEN];
} rds_acct_term_cause_t;

static const rds_acct_term_cause_t g_rds_acct_term_cause[] = {
    {RDS_ACCT_TERM_CAUSE_USER_REQUEST, "User request"},
    {RDS_ACCT_TERM_CAUSE_LOST_CARRIER, "Lost carrier"}, 
    {RDS_ACCT_TERM_CAUSE_LOST_SERVICE, "Lost service"},
    {RDS_ACCT_TERM_CAUSE_IDLE_TIMEOUT, "Idle timeout"},
    {RDS_ACCT_TERM_CAUSE_SESSION_TIMEOUT, "Session timeout"},
    {RDS_ACCT_TERM_CAUSE_ADMIN_RESET, "Admin reset"},
    {RDS_ACCT_TERM_CAUSE_ADMIN_REBOOT, "Admin reboot"},
    {RDS_ACCT_TERM_CAUSE_PORT_ERROR, "Port error"},
    {RDS_ACCT_TERM_CAUSE_NAS_ERROR, "Nas error"},
    {RDS_ACCT_TERM_CAUSE_NAS_REQUEST, "Nas request"},
    {RDS_ACCT_TERM_CAUSE_PORT_UNNEEDED, "Port unneeded"},
    {RDS_ACCT_TERM_CAUSE_PORT_SUSPENDED, "Port suspended"},
    {RDS_ACCT_TERM_CAUSE_SERVICE_UNAVAILABLE, "Service unavailable"},
    {RDS_ACCT_TERM_CAUSE_CALLBACK, "Callback"},
    {RDS_ACCT_TERM_CAUSE_USER_ERROR, "User error"},
    {RDS_ACCT_TERM_CAUSE_HOST_REQUEST, "Host request"},
    {RDS_ACCT_TERM_CAUSE_SUPPLICANT_RESTART, "Supplicant restart"},
    {RDS_ACCT_TERM_CAUSE_REAUTH_FAIL, "Reauth fail"},
    {RDS_ACCT_TERM_CAUSE_PORT_REINIT, "Port reinit"},
    {RDS_ACCT_TERM_CAUSE_PORT_ADMIN_DISABLED, "Port admin disabled"},
    {RDS_ACCT_TERM_CAUSE_HELLO_TIMEOUT, "Hello timeout"},
    {RDS_ACCT_TERM_CAUSE_LOW_FLOW_DETECT, "Low flow detect"},
    {RDS_ACCT_TERM_CAUSE_AUTHEN_TIMEOUT, "Authen timeout"},
    {RDS_ACCT_TERM_CAUSE_AUTHEN_REJECT, "Authen reject"},
    {RDS_ACCT_TERM_CAUSE_OVER_USER_LIMIT, "Over user limit"},
    {RDS_ACCT_TERM_CAUSE_UNKNOWN, "Unknown"},
};

int username_roles_name_len(local_user_t *user)
{
    username_role_name_t *role, *n;
    int i;

    i = 0;
    if(user == NULL) {
        return 0;
    }
    if (user->roles.num > 0) {
        list_for_each_entry_safe(role, n, &user->roles.list, list) {
            i += strlen(role->name);
        }
    }

    return i;
}

const char *rds_acct_term_cause_string(int term_cause_code)
{
    int i;
    const rds_acct_term_cause_t *term_cause;

    i = 0;
    term_cause = &g_rds_acct_term_cause[i];
    while (term_cause->term_cause_code != RDS_ACCT_TERM_CAUSE_UNKNOWN) {
        if (term_cause->term_cause_code == term_cause_code) {
            return term_cause->str;
        }
        i++;
        term_cause = &g_rds_acct_term_cause[i];
    }

    return NULL;
}

/*
 * aaa_show_msg_stat - 输出aaa消息的统计信息
 * @output - output func, normally is cli_printf
 */
void aaa_show_msg_stat(AAA_OUTPUT output)
{
    if (output == NULL) {
        return;
    }

    output("aaa message call send error times: %u"AAA_LINESEP, g_aaa_msg_stat.send_err_times); 
    output("aaa message call send again times: %u"AAA_LINESEP, g_aaa_msg_stat.send_again_times);
    output("aaa message call recv fail times: %u"AAA_LINESEP, g_aaa_msg_stat.recv_err_times);
    output("aaa message resend discard num: %u"AAA_LINESEP, g_aaa_msg_stat.resend_discard_msg_num);
    output("aaa malloc times: %u"AAA_LINESEP, g_aaa_malloc_times);
    output("aaa free times: %u"AAA_LINESEP, g_aaa_free_times);
    if (g_aaa_msg_stat.err_no != 0) {
        output("aaa message error socket(%d): %s"AAA_LINESEP, 
               g_aaa_msg_stat.sd, strerror(g_aaa_msg_stat.err_no));
    }
    
    return;
}

/**
 * aaa_make_dir - make directory according to path
 *
 * @path: pathname of directory to make
 *
 * 根据path提供的路径创建相应的目录层次，
 * path的格式应为"/abc/dfd/dfd"，或者"./abc/def"
 * 函数不检查path的格式，
 * 其格式由调用者保证
 *
 * 成功返回0；失败是返回errno
 */
int aaa_make_dir(char *path)
{
    int rv;
    char *token;
    char tmp_path[AAA_PATH_LEN_MAX];
    char buf[AAA_PATH_LEN_MAX];
    char pwd[PWD_PATH_LEN_MAX];

    if (path == NULL) {
        return EINVAL;
    }
    
    memset(buf, 0, sizeof(buf));
    if (strlen(path) > 2 && path[0] == '.' && path[1] == '/') {
        memset(pwd, 0, PWD_PATH_LEN_MAX);
        if (getcwd(pwd, PWD_PATH_LEN_MAX)) {
            strncpy(buf, pwd, AAA_PATH_LEN_MAX - 1);
            if (strlen(path) + strlen(pwd) < AAA_PATH_LEN_MAX) {
                /* coverity检查修订，实际上if已经判断了，这里为了健壮性考虑修订 */
                strncat(buf, &path[1], sizeof(buf) - strlen(buf) - 1);
            } else {
                return -1;
            }
        } else {
            return -1;
        }
    } else if (path[0] == '/') {
        strncpy(buf, path, AAA_PATH_LEN_MAX - 1);
    } else {
        return -1;
    }

    memset(tmp_path, 0, AAA_PATH_LEN_MAX);
    tmp_path[0] = '/';
    token = strtok(buf, "/");
    while (token != NULL) {
        if ((strlen(tmp_path) + strlen(token) + 1) >  AAA_PATH_LEN_MAX - 1) {
            return -1;
        }

        strcat(tmp_path, token);
        strcat(tmp_path, "/");
        rv = mkdir(tmp_path, S_IRWXU | S_IRWXG | S_IRWXO);
        if (rv != 0 && errno != EEXIST) {
            return errno;
        }

        token = strtok(NULL, "/");
    }

    return 0;
}

/**
 * aaa_msg_recv - 从sd接收len长度的消息，存放在buf中
 *
 * @sd: 接收消息的socket
 * @buf：消息存放的缓存
 * @len：接收消息的长度
 *
 * 循环接收消息，直至期望的消息长度。如果接收发生错误，返回错误码。
 *
 * 成功返回0；失败是返回errno
 */
int aaa_msg_recv(int sd, char *buf, int len)
{
    int left;
    int rcvlen;
    long time_start;
    
    if (buf == NULL || sd < 0) {
        return EINVAL;
    }
    /* 外部socket已设置超时，这里无需再设置 */
    time_start = AAA_NOW;

    left = len;
    while (left > 0 && (AAA_NOW - time_start) < 10) {
        rcvlen = recv(sd, (void *)(buf + (len - left)), left, 0);
        if (rcvlen > 0) {/* 接收到rcvlen个字节 */
            left -= rcvlen;
        } else if (rcvlen < 0) {/* 发生错误 */
            if (errno != EINTR && errno != EWOULDBLOCK && errno != EAGAIN) {
                g_aaa_msg_stat.recv_err_times++;
                g_aaa_msg_stat.sd = sd;
                g_aaa_msg_stat.err_no = errno;
                return errno;
            }
        } else {/* the peer has performed an orderly shutdown */
            g_aaa_msg_stat.recv_err_times++;
            g_aaa_msg_stat.sd = sd;
            g_aaa_msg_stat.err_no = errno;
            return EPIPE;
        }
    }

    return left == 0 ? left : errno;
}

/**
 * aaa_msg_send - use send_flag to send msg in sd , 
 *
 * @sd: send sd
 * @msg: message send 
 * @msg_len: message length
 * @send_flag: send flag
 *
 * return: 0 when send success, other return errno
 */
int aaa_msg_send(int sd, char *msg, int msg_len, int send_flag)
{
    int send_bytes;
    int send_time;
    long time_start;

    if (msg == NULL || msg_len <= 0 || sd < 0) {
        return EINVAL;
    }

    time_start = AAA_NOW;
    send_time = 0;
    while (msg_len > 0 && (AAA_NOW - time_start) < 10) {
        send_bytes = send(sd, msg, msg_len, send_flag);

        if (send_bytes < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                g_aaa_msg_stat.send_again_times++;
                g_aaa_msg_stat.sd = sd;
                g_aaa_msg_stat.err_no = errno;
                send_time++;
                if (send_time >= AAA_SOCKET_RESEND_MAX_TIMES) {
                    g_aaa_msg_stat.resend_discard_msg_num++;
                    return errno;
                }
                usleep(100000);
                continue;
            } else {
                g_aaa_msg_stat.send_err_times++;
                g_aaa_msg_stat.sd = sd;
                g_aaa_msg_stat.err_no = errno;
                return errno;
            }
        }

        msg_len -= send_bytes;
        msg += send_bytes;
    }

    return msg_len == 0 ? msg_len : errno;
}


static void aaa_cpy_value(aaa_iovec_t *iovec_tlv, tlv_t *tlv, int *pos)
{
    if (tlv->len > 0) {
        memcpy(&iovec_tlv->data[*pos], tlv->data, tlv->len);
        tlv->data = &iovec_tlv->data[*pos];
        *pos += TLV_STR_LEN(tlv);
    } else {
        tlv->data = NULL;
    }

    return;
}

static void aaa_cpy_tlv(tlv_t *tlv, ushort type, ushort attr_len, char *buf, int *len)
{
    tlv->type = type;
    tlv->len = attr_len;
    tlv->data = (uchar *)&buf[*len];
    *len += attr_len;

    return;
}

/**
 * aaa_init_msg - init the aaa message to send
 *
 * @type: message type
 * @data: data to send
 * @data_len: length of data to send
 * @msg_len: the whole msg len
 *
 * 使用三个参数来填充aaa_ipc_msg_t的三个变量，参数data允许为NULL，表示报文内容为空
 *
 * 成功返回aaa_ipc_msg_t指针，失败返回NULL
 */
aaa_ipc_msg_t *aaa_init_msg(int type, uint session_id, const char *data, int data_len, int *msg_len)
{
    aaa_ipc_msg_t *msg;
    int len;

    if (data == NULL) {
        data_len = 0;
    }
    len = data_len + sizeof(aaa_ipc_msg_t);
    msg = (aaa_ipc_msg_t *)AAA_ALLOC(len);
    if (msg == NULL) {
        return NULL;
    }
    memset(msg, 0, len);
    msg->aaa_id = AAA_ID;
    msg->session_id = session_id;
    msg->msg_type = type;
    msg->msg_len = data_len;
    if (data != NULL && data_len > 0) {
        memcpy(msg->msg, data, data_len);
    }
    *msg_len = len;

    return msg;
}

/**
 * aaa_send_ipc_msg - send msg
 *
 * @sd: socket to send msg
 * @type: msg type
 * @pkt: msg data
 * @pkt_len: msg data len
 *
 * 把pak所指的数据组装成type类型的报文通过sd发送出去。调用者保证pak为NULL时，pak_len为0
 *
 * 成功返回SUCCESS，失败返回errno
 */
int aaa_send_ipc_msg(int sd, aaa_ipc_type_t type, char *pkt, int pkt_len)
{
    int msg_len;
    aaa_ipc_msg_t *send_msg;
    int ret;

    /*xxx 调用这个接口的消息都是没有session id的 */
    send_msg = aaa_init_msg(type, 0, pkt, pkt_len, &msg_len);
    if (send_msg == NULL) {
        return ENOMEM;
    }

    ret = aaa_msg_send(sd, (char *)send_msg, msg_len, MSG_WAITALL);
    AAA_FREE(send_msg);

    return ret;
}

aaa_ipc_msg_t *aaa_recv_ipc_msg_from_sd(int sd)
{
    aaa_ipc_msg_t msg_header;
    aaa_ipc_msg_t *whole_msg;
    int ioret;

    /* receive ipc msg header */
    ioret = aaa_msg_recv(sd, (char *)&msg_header, sizeof(msg_header));
    if (ioret != SUCCESS) {
        return NULL;
    }

    /* receive whole msg */
    whole_msg = (aaa_ipc_msg_t *)AAA_ALLOC(sizeof(*whole_msg) + msg_header.msg_len);
    if (whole_msg == NULL) {
        return NULL;
    }
    memcpy(whole_msg, &msg_header, sizeof(msg_header));
    if (whole_msg->msg_len > 0) {
        ioret = aaa_msg_recv(sd, whole_msg->msg, whole_msg->msg_len);
        if (ioret != SUCCESS) {
            AAA_FREE(whole_msg);
            return NULL;
        }
    }

    return whole_msg;
}

static int aaa_authen_mid_info_len(authen_info_t *s)
{
    int len;

    len = sizeof(authen_info_sub_ipc_t) + 2 * sizeof(ushort);
    TLV_ADD_WHOLE_LEN(len, &s->name);
    TLV_ADD_WHOLE_LEN(len, &s->pwd);
    TLV_ADD_WHOLE_LEN(len, &s->response);
    TLV_ADD_WHOLE_LEN(len, &s->challenge);
    TLV_ADD_WHOLE_LEN(len, &s->eap_msg);
    TLV_ADD_WHOLE_LEN(len, &s->state);
    TLV_ADD_WHOLE_LEN(len, &s->no_change);
    TLV_ADD_WHOLE_LEN(len, &s->cui);
    TLV_ADD_WHOLE_LEN(len, &s->terminal_type);
    TLV_ADD_WHOLE_LEN(len, &s->rds_name);
    
    len += TLV_HEADER_LEN;
    if (s->udata != NULL && s->sub.udata_len > 0) {
        len += s->sub.udata_len;
    }
    len += TLV_HEADER_LEN;
    if (s->mlist != NULL) {
        len += strlen(s->mlist);
    }
    len += TLV_HEADER_LEN;
    if (s->role != NULL && s->sub.rbac_len > 0 && s->sub.rbac_flag) {
        len += s->sub.rbac_len;
    }
    len += (TLV_HEADER_LEN + s->iov.used);

    return len;
}

static int aaa_author_mid_info_len(author_info_t *s)
{
    int len;

    len = sizeof(author_info_sub_ipc_t) + 2 * sizeof(ushort);
    TLV_ADD_WHOLE_LEN(len, &s->name);

    len += TLV_HEADER_LEN;
    if (s->mlist != NULL) {
        len += strlen(s->mlist);
    }

    len += (TLV_HEADER_LEN + s->iov.used);

    return len;
}

static int aaa_acct_mid_info_len(acct_info_t *s)
{
    int len;

    len = sizeof(acct_info_sub_ipc_t) + 2 * sizeof(ushort);
    TLV_ADD_WHOLE_LEN(len, &s->username);
    TLV_ADD_WHOLE_LEN(len, &s->class_attr);
    TLV_ADD_WHOLE_LEN(len, &s->cui);
    TLV_ADD_WHOLE_LEN(len, &s->terminal_type);

    len += TLV_HEADER_LEN;
    if (s->mlist != NULL) {
        len += strlen(s->mlist);
    }
    len += TLV_HEADER_LEN;
    if(s->sub.rbac_flag && s->sub.rbac_len > 0 && s->role != NULL) {
        len += s->sub.rbac_len;
    }

    len += (TLV_HEADER_LEN + s->iov.used);

    return len;
}

static int aaa_result_mid_info_len(aaa_result_t *s)
{
    int len;

    len = sizeof(aaa_result_sub_ipc_t) + 2 * sizeof(ushort);
    len += (TLV_HEADER_LEN + s->mppe_key.recv_key_len);
    len += (TLV_HEADER_LEN + s->mppe_key.send_key_len);
    TLV_ADD_WHOLE_LEN(len, &s->class_attr);
    TLV_ADD_WHOLE_LEN(len, &s->unknown);
    TLV_ADD_WHOLE_LEN(len, &s->eap_msg);
    TLV_ADD_WHOLE_LEN(len, &s->state);
    TLV_ADD_WHOLE_LEN(len, &s->reply_msg);
    TLV_ADD_WHOLE_LEN(len, &s->cui);
    TLV_ADD_WHOLE_LEN(len, &s->mschap_resp);
    TLV_ADD_WHOLE_LEN(len, &s->username);
    
    len += TLV_HEADER_LEN;
    if (s->udata != NULL && s->sub.udata_len > 0) {
        len += s->sub.udata_len;
    }
    len += TLV_HEADER_LEN;
    if (s->role != NULL && s->sub.rbac_len > 0) {
        len += s->sub.rbac_len;
    }
    len += (TLV_HEADER_LEN + s->iov.used);

    return len;
}

/**
 * aaa_encap_authen_info - 把authen_info_t的结构封装成字节流
 *
 * @authen: 要封装的结构
 * @pak: 封装后的字节流
 *
 * 把authen_info_t的结构封装成字节流
 *
 * 成功返回封装的报文长度，否则返回0
 */
int aaa_encap_authen_info(authen_info_t *authen, char **pak)
{
    char *packet;
    int len;
    int pos;
    ushort ulen;
    ushort type;
    authen_info_sub_ipc_t ipc_sub;
    tlv_t tlv;

    if (authen == NULL || pak == NULL) {
        return 0;
    }

    len = aaa_authen_mid_info_len(authen);
    packet = AAA_ALLOC(len);
    if (packet == NULL) {
        return 0;
    }
    memset(packet, 0 ,len);
    memset(&tlv, 0, sizeof(tlv));

    aaa_encap_authen_info_sub(&ipc_sub, &authen->sub);
    pos = 0;
    tlv.type = TYPE_SUB_STRUCT;
    tlv.data = (uchar *)&ipc_sub;
    tlv.len = (ushort)sizeof(authen_info_sub_ipc_t);
    CPY_DATA_ENCAP_TLV(packet, tlv, sizeof(ushort), pos);
    authen->name.type = TYPE_USERNAME;
    CPY_DATA_ENCAP_TLV(packet, authen->name, sizeof(ushort), pos);
    authen->pwd.type = TYPE_PWD;
    CPY_DATA_ENCAP_TLV(packet, authen->pwd, sizeof(ushort), pos);
    authen->response.type = TYPE_RESPONSE;
    CPY_DATA_ENCAP_TLV(packet, authen->response, sizeof(ushort), pos);
    authen->challenge.type = TYPE_CHALLENGE;
    CPY_DATA_ENCAP_TLV(packet, authen->challenge, sizeof(ushort), pos);
    authen->eap_msg.type = TYPE_EAP_MSG;
    CPY_DATA_ENCAP_TLV(packet, authen->eap_msg, sizeof(ushort), pos);
    authen->state.type = TYPE_STATE;
    CPY_DATA_ENCAP_TLV(packet, authen->state, sizeof(ushort), pos);
    authen->no_change.type = TYPE_NO_CHANGE;
    CPY_DATA_ENCAP_TLV(packet, authen->no_change, sizeof(ushort), pos);
    authen->cui.type = TYPE_CUI;
    CPY_DATA_ENCAP_TLV(packet, authen->cui, sizeof(ushort), pos);
    authen->terminal_type.type = TYPE_TERMINAL_TYPE;
    CPY_DATA_ENCAP_TLV(packet, authen->terminal_type, sizeof(ushort), pos);
    authen->rds_name.type = TYPE_RDS_NAME;
    CPY_DATA_ENCAP_TLV(packet, authen->rds_name, sizeof(ushort), pos);
    
    /* udata ,mlist, iov_data单独处理 */
    type = TYPE_UDATA;
    CPY_DATA_ENCAP(packet, type, sizeof(ushort), pos);
    if (authen->sub.udata_len > 0) {
        ulen = (ushort)authen->sub.udata_len;
        CPY_DATA_ENCAP(packet, ulen, sizeof(ushort), pos);
        if (ulen > 0) {
            memcpy(&packet[pos], authen->udata, ulen);
            pos += ulen;
        }
    } else {
        ulen = 0;
        CPY_DATA_ENCAP(packet, ulen, sizeof(ushort), pos);
    }

    type = TYPE_MLIST;
    CPY_DATA_ENCAP(packet, type, sizeof(ushort), pos);
    if (authen->mlist != NULL) {
        ulen = (ushort)strlen(authen->mlist);
        CPY_DATA_ENCAP(packet, ulen, sizeof(ushort), pos);
        if (ulen > 0) {
            memcpy(&packet[pos], authen->mlist, ulen);
            pos += ulen;
        }
    } else {
        ulen = 0;
        CPY_DATA_ENCAP(packet, ulen, sizeof(ushort), pos);
    }

    type = TYPE_ROLE_NAME;
    CPY_DATA_ENCAP(packet, type, sizeof(ushort), pos);
    if (authen->role != NULL && authen->sub.rbac_len > 0 && authen->sub.rbac_flag) {
        ulen = (ushort)authen->sub.rbac_len;
        CPY_DATA_ENCAP(packet, ulen, sizeof(ushort), pos);
        if (ulen > 0) {
            memcpy(&packet[pos], authen->role, ulen);
            pos += ulen;
        }
    } else {
        ulen = 0;
        CPY_DATA_ENCAP(packet, ulen, sizeof(ushort), pos);
    }

    type = TYPE_IOV_DATA;
    ulen = (ushort)authen->iov.used;
    CPY_DATA_ENCAP(packet, type, sizeof(ushort), pos);
    CPY_DATA_ENCAP(packet, ulen, sizeof(ushort), pos);
    if (ulen > 0) {
        memcpy(&packet[pos], authen->iov.data, ulen);
        pos += ulen;
    }

    *pak = packet;
    return len;
}

/**
 * aaa_encap_author_info - 把author_info_t的结构封装成字节流
 *
 * @author: 要封装的结构
 * @pak: 封装后的字节流
 *
 * 把author_info_t的结构封装成字节流
 *
 * 成功返回封装的报文长度，否则返回0
 */
int aaa_encap_author_info(author_info_t *author, char **pak)
{
    char *packet;
    int len;
    int pos;
    ushort ulen;
    ushort type;
    author_info_sub_ipc_t ipc_sub;
    tlv_t tlv;

    if (author == NULL || pak == NULL) {
        return 0;
    }

    len = aaa_author_mid_info_len(author);

    packet = AAA_ALLOC(len);
    if (packet == NULL) {
        return 0;
    }
    memset(packet, 0 ,len);
    memset(&tlv, 0, sizeof(tlv));

    aaa_encap_author_info_sub(&ipc_sub, &author->sub);
    pos = 0;
    tlv.type = TYPE_SUB_STRUCT;
    tlv.data = (uchar*)&ipc_sub;
    tlv.len = (short)sizeof(author_info_sub_ipc_t);
    CPY_DATA_ENCAP_TLV(packet, tlv, sizeof(ushort), pos);
    author->name.type = TYPE_USERNAME;
    CPY_DATA_ENCAP_TLV(packet, author->name, sizeof(ushort), pos);

    /* mlist, iov_data单独处理 */
    type = TYPE_MLIST;
    CPY_DATA_ENCAP(packet, type, sizeof(ushort), pos);
    if (author->mlist != NULL) {
        ulen = (ushort)strlen(author->mlist);
        CPY_DATA_ENCAP(packet, ulen, sizeof(ushort), pos);
        if (ulen > 0) {
            memcpy(&packet[pos], author->mlist, ulen);
            pos += ulen;
        }
    } else {
        ulen = 0;
        CPY_DATA_ENCAP(packet, ulen, sizeof(ushort), pos);
    }

    type = TYPE_IOV_DATA;
    ulen = (ushort)author->iov.used;
    CPY_DATA_ENCAP(packet, type, sizeof(ushort), pos);
    CPY_DATA_ENCAP(packet, ulen, sizeof(ushort), pos);
    if (ulen > 0) {
        memcpy(&packet[pos], author->iov.data, ulen);
        pos += ulen;
    }

    *pak = packet;
    return len;
}

/**
 * aaa_encap_acct_info - 把acct_info_t的结构封装成字节流
 *
 * @acct: 要封装的结构
 * @pak: 封装后的字节流
 *
 * 把acct_info_t的结构封装成字节流
 *
 * 成功返回封装的报文长度，否则返回0
 */
int aaa_encap_acct_info(acct_info_t *acct, char **pak)
{
    char *packet;
    int len;
    int pos;
    ushort ulen;
    ushort type;
    acct_info_sub_ipc_t ipc_sub;
    tlv_t tlv;

    if (acct == NULL || pak == NULL) {
        return 0;
    }

    len = aaa_acct_mid_info_len(acct);

    packet = AAA_ALLOC(len);
    if (packet == NULL) {
        return 0;
    }
    memset(packet, 0 ,len);
    memset(&tlv, 0, sizeof(tlv));

    aaa_encap_acct_info_sub(&ipc_sub, &acct->sub);
    pos = 0;
    tlv.type = TYPE_SUB_STRUCT;
    tlv.data = (uchar*)&ipc_sub;
    tlv.len = (ushort)sizeof(acct_info_sub_ipc_t);
    CPY_DATA_ENCAP_TLV(packet, tlv, sizeof(ushort), pos);
    acct->username.type = TYPE_USERNAME;
    CPY_DATA_ENCAP_TLV(packet, acct->username, sizeof(ushort), pos);
    acct->class_attr.type = TYPE_CLASS_ATTR;
    CPY_DATA_ENCAP_TLV(packet, acct->class_attr, sizeof(ushort), pos);
    acct->cui.type = TYPE_CUI;
    CPY_DATA_ENCAP_TLV(packet, acct->cui, sizeof(ushort), pos);
    acct->terminal_type.type = TYPE_TERMINAL_TYPE;
    CPY_DATA_ENCAP_TLV(packet, acct->terminal_type, sizeof(ushort), pos);

    /* mlist, iov_data单独处理 */
    type = TYPE_MLIST;
    CPY_DATA_ENCAP(packet, type, sizeof(ushort), pos);
    if (acct->mlist) {
        ulen = strlen(acct->mlist);
        CPY_DATA_ENCAP(packet, ulen, sizeof(ushort), pos);
        if (ulen > 0) {
            memcpy(&packet[pos], acct->mlist, ulen);
            pos += ulen;
        }
    } else {
        ulen = 0;
        CPY_DATA_ENCAP(packet, ulen, sizeof(ushort), pos);
    }

    type = TYPE_ROLE_NAME;
    CPY_DATA_ENCAP(packet, type, sizeof(ushort), pos);
    if (acct->sub.rbac_flag && acct->sub.rbac_len > 0 && acct->role != NULL) {
        ulen = (ushort)acct->sub.rbac_len;
        CPY_DATA_ENCAP(packet, ulen, sizeof(ushort), pos);
        if (ulen > 0) {
            memcpy(&packet[pos], acct->role, ulen);
            pos += ulen;
        }
    } else {
        ulen = 0;
        CPY_DATA_ENCAP(packet, ulen, sizeof(ushort), pos);
    }

    type = TYPE_IOV_DATA;
    ulen = (ushort)acct->iov.used;
    CPY_DATA_ENCAP(packet, type, sizeof(ushort), pos);
    CPY_DATA_ENCAP(packet, ulen, sizeof(ushort), pos);
    if (ulen > 0) {
        memcpy(&packet[pos], acct->iov.data, ulen);
        pos += ulen;
    }

    *pak = packet;
    return len;
}

/**
 * aaa_encap_result_info - 把aaa_result_t的结构封装成字节流
 *
 * @result: 要封装的结构
 * @pak: 封装后的字节流
 *
 * 把aaa_result_t的结构封装成字节流
 *
 * 成功返回封装的报文长度，否则返回0
 */
int aaa_encap_result_info(aaa_result_t *result, char **pak)
{
    char *packet;
    int len;
    int pos;
    ushort ulen;
    ushort type;
    aaa_result_sub_ipc_t ipc_sub;
    tlv_t tlv;

    if (result == NULL || pak == NULL) {
        return 0;
    }

    len = aaa_result_mid_info_len(result);
    packet = AAA_ALLOC(len);
    if (packet == NULL) {
        return 0;
    }
    memset(packet, 0 ,len);
    memset(&tlv, 0, sizeof(tlv));

    aaa_encap_result_info_sub(&ipc_sub, &result->sub);
    pos = 0;
    tlv.type = TYPE_SUB_STRUCT;
    tlv.data = (uchar*)&ipc_sub;
    tlv.len = (ushort)sizeof(aaa_result_sub_ipc_t);
    CPY_DATA_ENCAP_TLV(packet, tlv, sizeof(ushort), pos);
    result->unknown.type = TYPE_UNKNOWN;
    CPY_DATA_ENCAP_TLV(packet, result->unknown, sizeof(ushort), pos);
    result->reply_msg.type = TYPE_REPLY_MSG;
    CPY_DATA_ENCAP_TLV(packet, result->reply_msg, sizeof(ushort), pos);
    result->class_attr.type = TYPE_CLASS_ATTR;
    CPY_DATA_ENCAP_TLV(packet, result->class_attr, sizeof(ushort), pos);
    result->eap_msg.type = TYPE_EAP_MSG;
    CPY_DATA_ENCAP_TLV(packet, result->eap_msg, sizeof(ushort), pos);
    result->username.type = TYPE_USERNAME;
    CPY_DATA_ENCAP_TLV(packet, result->username, sizeof(ushort), pos);
    result->state.type = TYPE_STATE;
    CPY_DATA_ENCAP_TLV(packet, result->state, sizeof(ushort), pos);
    result->cui.type = TYPE_CUI;
    CPY_DATA_ENCAP_TLV(packet, result->cui, sizeof(ushort), pos);
    result->mschap_resp.type = TYPE_MSCHAP_RESP;
    CPY_DATA_ENCAP_TLV(packet, result->mschap_resp, sizeof(ushort), pos);

    /* udata,iov_data等单独处理 */
    type = TYPE_UDATA;
    CPY_DATA_ENCAP(packet, type, sizeof(ushort), pos);
    if (result->sub.udata_len > 0) {
        ulen = result->sub.udata_len;
        CPY_DATA_ENCAP(packet, ulen, sizeof(ushort), pos);
        if (ulen > 0) {
            memcpy(&packet[pos], result->udata, ulen);
            pos += ulen;
        }
    } else {
        ulen = 0;
        CPY_DATA_ENCAP(packet, ulen, sizeof(ushort), pos);
    }

    type = TYPE_MPPE_SEND_KEY;
    ulen = (ushort)result->mppe_key.send_key_len;
    CPY_DATA_ENCAP(packet, type, sizeof(ushort), pos);
    CPY_DATA_ENCAP(packet, ulen, sizeof(ushort), pos);
    if (ulen > 0) {
        memcpy(&packet[pos], result->mppe_key.send_key, ulen);
        pos += ulen;
    }

    type = TYPE_MPPE_RECV_KEY;
    ulen = (ushort)result->mppe_key.recv_key_len;
    CPY_DATA_ENCAP(packet, type, sizeof(ushort), pos);
    CPY_DATA_ENCAP(packet, ulen, sizeof(ushort), pos);
    if (ulen > 0) {
        memcpy(&packet[pos], result->mppe_key.recv_key, ulen);
        pos += ulen;
    }

    type = TYPE_IOV_DATA;
    ulen = (ushort)result->iov.used;
    CPY_DATA_ENCAP(packet, type, sizeof(ushort), pos);
    CPY_DATA_ENCAP(packet, ulen, sizeof(ushort), pos);
    if (ulen > 0) {
        memcpy(&packet[pos], result->iov.data, ulen);
        pos += ulen;
    }
    type = TYPE_ROLE_NAME;
    CPY_DATA_ENCAP(packet, type, sizeof(ushort), pos);
    if (result->sub.rbac_len > 0 && result->sub.rbac_flag && result->role != NULL) {
        ulen = result->sub.rbac_len;
        CPY_DATA_ENCAP(packet, ulen, sizeof(ushort), pos);
        if (ulen > 0) {
            memcpy(&packet[pos], result->role, ulen);
            pos += ulen;
        }
    } else {
        ulen = 0;
        CPY_DATA_ENCAP(packet, ulen, sizeof(ushort), pos);
    }

    *pak = packet;
    return len;
}

/**
 * aaa_parse_authen_info - 把接收到的网络字节流buf解析成authen_info_t结构
 *
 * @authe: 存放解析的结果
 * @buf: 要解析的字节流
 * @msg_len: 字节流的长度
 *
 * 把接收到的网络字节流buf解析成authen_info_t结构，buf是从socket收到的数据，没有msg_type和msg_len
 *
 * 解析失败，返回0；否则返回非0
 */
int aaa_parse_authen_info(authen_info_t **authe, char *buf, int msg_len)
{
    int len;
    int pos;
    int tlv_len;
    ushort type;
    ushort attr_len;
    authen_info_t *authen;
    authen_info_sub_ipc_t *ipc_sub;

    if (buf == NULL || authe == NULL) {
        return 0;
    }
    
    if (msg_len < sizeof(authen_info_sub_ipc_t)) {
        /* 报文长度非法，解析失败 */
        return 0;
    }

    authen = AAA_ALLOC(sizeof(authen_info_t));
    if (authen == NULL) {
        return 0;
    }
    memset(authen, 0, sizeof(authen_info_t));

    len = 0;
    tlv_len = 0;
    /* 接下来都是tlv的数据,T和L都是ushort类型 */
    while (len < msg_len) {
        memcpy((void*)&type, &buf[len], sizeof(ushort));
        len += sizeof(ushort);

        memcpy((void*)&attr_len, &buf[len], sizeof(ushort));
        len += sizeof(ushort);

        switch (type) {
        case TYPE_SUB_STRUCT:
            if (attr_len == sizeof(authen_info_sub_ipc_t)) {
                ipc_sub = (authen_info_sub_ipc_t *)&buf[len];
                aaa_parse_authen_info_sub(&authen->sub, ipc_sub);
            }
            len += attr_len;
            break;
        case TYPE_USERNAME:
            aaa_cpy_tlv(&authen->name, type, attr_len, buf, &len);
            break;

        case TYPE_PWD:
            aaa_cpy_tlv(&authen->pwd, type, attr_len, buf, &len);
            break;

        case TYPE_RESPONSE:
            aaa_cpy_tlv(&authen->response, type, attr_len, buf, &len);
            break;

        case TYPE_CHALLENGE:
            aaa_cpy_tlv(&authen->challenge, type, attr_len, buf, &len);

            break;

        case TYPE_EAP_MSG:
            aaa_cpy_tlv(&authen->eap_msg, type, attr_len, buf, &len);
            break;

        case TYPE_STATE:
            aaa_cpy_tlv(&authen->state, type, attr_len, buf, &len);

            break;

        case TYPE_NO_CHANGE:
            aaa_cpy_tlv(&authen->no_change, type, attr_len, buf, &len);

            break;

        case TYPE_CUI:
            aaa_cpy_tlv(&authen->cui, type, attr_len, buf, &len);

            break;

        case TYPE_TERMINAL_TYPE:
            aaa_cpy_tlv(&authen->terminal_type, type, attr_len, buf, &len);

            break;

        case TYPE_RDS_NAME:
            aaa_cpy_tlv(&authen->rds_name, type, attr_len, buf, &len);
            break;
        
        case TYPE_UDATA:
            if (attr_len > 0) {
                authen->udata = AAA_ALLOC(attr_len);
                if (authen->udata == NULL) {
                    len += attr_len;
                    break;
                }
                memset(authen->udata, 0, attr_len);
                memcpy(authen->udata, &buf[len], attr_len);
                len += attr_len;
            }

            break;

        case TYPE_IOV_DATA:
            if (attr_len > 0) {
                authen->iov.data = AAA_ALLOC(attr_len + 1);
                if (authen->iov.data == NULL) {
                    len += attr_len;
                    break;
                }
                memset(authen->iov.data, 0, attr_len + 1);
                memcpy(authen->iov.data, &buf[len], attr_len);
                len += attr_len;
                authen->iov.used += attr_len;
                authen->iov.left = 0;
            }
            break;

        case TYPE_MLIST:
            if (attr_len > 0) {
                authen->mlist = AAA_ALLOC(attr_len + 1);
                if (authen->mlist == NULL) {
                    len += attr_len;
                    break;
                }
                memset(authen->mlist, 0, attr_len + 1);
                memcpy(authen->mlist, &buf[len], attr_len);
                len += attr_len;
            }

            break;

        case TYPE_ROLE_NAME:
            if (attr_len > 0) {
                if (authen->sub.rbac_flag){
                    authen->role = AAA_ALLOC(attr_len);
                    if (authen->role == NULL) {
                        len += attr_len;
                        break;
                    }
                    memset(authen->role, 0, attr_len);
                    memcpy(authen->role, &buf[len], attr_len);
                }
                len += attr_len;
            }

            break;

        default:
            break;
        }
    }

    tlv_len += TLV_STR_LEN(&authen->name);
    tlv_len += TLV_STR_LEN(&authen->pwd);
    tlv_len += TLV_STR_LEN(&authen->response);
    tlv_len += TLV_STR_LEN(&authen->challenge);
    tlv_len += TLV_STR_LEN(&authen->eap_msg);
    tlv_len += TLV_STR_LEN(&authen->state);
    tlv_len += TLV_STR_LEN(&authen->no_change);
    tlv_len += TLV_STR_LEN(&authen->cui);
    tlv_len += TLV_STR_LEN(&authen->terminal_type);
    tlv_len += TLV_STR_LEN(&authen->rds_name);
    
    authen->tlv.data = AAA_ALLOC(tlv_len);
    if (authen->tlv.data == NULL) {
        AAA_FREE((char *)authen->iov.data);
        AAA_FREE(authen->mlist);
        AAA_FREE(authen->udata);
        AAA_FREE(authen->role);
        AAA_FREE(authen);
        return 0;
    }
    memset(authen->tlv.data, 0, tlv_len);
    authen->tlv.used = tlv_len;
    authen->tlv.left = 0;

    pos = 0;
    aaa_cpy_value(&authen->tlv, &authen->name, &pos);
    aaa_cpy_value(&authen->tlv, &authen->pwd, &pos);
    aaa_cpy_value(&authen->tlv, &authen->response, &pos);
    aaa_cpy_value(&authen->tlv, &authen->challenge, &pos);
    aaa_cpy_value(&authen->tlv, &authen->eap_msg, &pos);
    aaa_cpy_value(&authen->tlv, &authen->state, &pos);
    aaa_cpy_value(&authen->tlv, &authen->no_change, &pos);
    aaa_cpy_value(&authen->tlv, &authen->cui, &pos);
    aaa_cpy_value(&authen->tlv, &authen->terminal_type, &pos);
    aaa_cpy_value(&authen->tlv, &authen->rds_name, &pos);
    
    *authe = authen;
    return 1;
}

/**
 * aaa_parse_author_info - 把接收到的网络字节流buf解析成author_info_t结构
 *
 * @autho: 存放解析的结果
 * @buf: 要解析的字节流
 * @msg_len: 字节流的长度
 *
 * 把接收到的网络字节流buf解析成author_info_t结构，buf是从socket收到的数据，没有msg_type和msg_len
 *
 * 解析失败，返回0；否则返回非0
 */
int aaa_parse_author_info(author_info_t **autho, char *buf, int msg_len)
{
    int len;
    int pos;
    int tlv_len;
    ushort type;
    ushort attr_len;
    author_info_t *author;
    author_info_sub_ipc_t *ipc_sub;

    if (buf == NULL || autho == NULL) {
        return 0;
    }

    if (msg_len < sizeof(author_info_sub_ipc_t)) {
        /* 报文长度非法，解析失败 */
        return 0;
    }

    author = (author_info_t *)AAA_ALLOC(sizeof(author_info_t));
    if (author == NULL) {
        return 0;
    }
    memset(author, 0, sizeof(author_info_t));

    len = 0;
    tlv_len = 0;
    /* 接下来都是tlv的数据,T和L都是ushort类型 */
    while (len < msg_len) {
        memcpy((void*)&type, &buf[len], sizeof(ushort));
        len += sizeof(ushort);

        memcpy((void*)&attr_len, &buf[len], sizeof(ushort));
        len += sizeof(ushort);

        switch (type) {
        case TYPE_SUB_STRUCT:
            if (attr_len == sizeof(author_info_sub_ipc_t)) {
                ipc_sub = (author_info_sub_ipc_t *)&buf[len];
                aaa_parse_author_info_sub(&author->sub, ipc_sub);
            }
            len += attr_len;
            break;
        case TYPE_USERNAME:
            aaa_cpy_tlv(&author->name, type, attr_len, buf, &len);
            break;

        case TYPE_IOV_DATA:
            if (attr_len > 0) {
                author->iov.data = AAA_ALLOC(attr_len + 1);
                if (author->iov.data == NULL) {
                    len += attr_len;
                    break;
                }
                memset(author->iov.data, 0, attr_len + 1);
                memcpy(author->iov.data, &buf[len], attr_len);
                len += attr_len;
                author->iov.used += attr_len;
                author->iov.left = 0;
            }
            break;

        case TYPE_MLIST:
            if (attr_len > 0) {
                author->mlist = AAA_ALLOC(attr_len + 1);
                if (author->mlist == NULL) {
                    len += attr_len;
                    break;
                }
                memset(author->mlist, 0, attr_len + 1);
                memcpy(author->mlist, &buf[len], attr_len);
                len += attr_len;
            }
            break;

        default:
            break;
        }
    }

    tlv_len += TLV_STR_LEN(&author->name);
    author->tlv.data = AAA_ALLOC(tlv_len);
    if (author->tlv.data == NULL) {
        AAA_FREE((char *)author->iov.data);
        AAA_FREE(author->mlist);
        AAA_FREE(author);
        return 0;
    }
    memset(author->tlv.data, 0, tlv_len);
    author->tlv.used = tlv_len;
    author->tlv.left = 0;
    pos = 0;
    aaa_cpy_value(&author->tlv, &author->name, &pos);
    *autho = author;
    return 1;
}

/**
 * aaa_parse_acct_info - 把接收到的网络字节流buf解析成acct_info_t结构
 *
 * @autho: 存放解析的结果
 * @buf: 要解析的字节流
 * @msg_len: 字节流的长度
 *
 * 把接收到的网络字节流buf解析成acct_info_t结构，buf是从socket收到的数据，没有msg_type和msg_len
 *
 * 解析失败，返回0；否则返回非0
 */
int aaa_parse_acct_info(acct_info_t **acc, char *buf, int msg_len)
{
    int len;
    int pos;
    int tlv_len;
    ushort type;
    ushort attr_len;
    acct_info_t * acct;
    acct_info_sub_ipc_t *ipc_sub;

    if (buf == NULL || acc == NULL) {
        return 0;
    }

    if (msg_len < sizeof(acct_info_sub_ipc_t)) {
        /* 报文长度非法，解析失败 */
        return 0;
    }

    acct = AAA_ALLOC(sizeof(acct_info_t));
    if (acct == NULL) {
        return 0;
    }
    memset(acct, 0, sizeof(acct_info_t));

    len = 0;
    tlv_len = 0;
    while (len < msg_len) {
        memcpy((void*)&type, &buf[len], sizeof(ushort));
        len += sizeof(ushort);

        memcpy((void*)&attr_len, &buf[len], sizeof(ushort));
        len += sizeof(ushort);

        switch (type) {
        case TYPE_SUB_STRUCT:
            if (attr_len == sizeof(acct_info_sub_ipc_t)) {
                ipc_sub = (acct_info_sub_ipc_t *)&buf[len];
                aaa_parse_acct_info_sub(&acct->sub, ipc_sub);
            }
            len += attr_len;
            break;
        case TYPE_USERNAME:
            aaa_cpy_tlv(&acct->username, type, attr_len, buf, &len);
            break;

        case TYPE_CUI:
            aaa_cpy_tlv(&acct->cui, type, attr_len, buf, &len);
            break;

        case TYPE_CLASS_ATTR:
            aaa_cpy_tlv(&acct->class_attr, type, attr_len, buf, &len);
            break;

        case TYPE_TERMINAL_TYPE:
            aaa_cpy_tlv(&acct->terminal_type, type, attr_len, buf, &len);
			break;
        case TYPE_IOV_DATA:
            if (attr_len > 0) {
                acct->iov.data = AAA_ALLOC(attr_len + 1);
                if (acct->iov.data == NULL) {
                    len += attr_len;
                    break;
                }
                memset(acct->iov.data, 0, attr_len + 1);
                memcpy(acct->iov.data, &buf[len], attr_len);
                len += attr_len;
                acct->iov.used += attr_len;
                acct->iov.left = 0;
            }
            break;

        case TYPE_MLIST:
            if (attr_len > 0) {
                acct->mlist = AAA_ALLOC(attr_len + 1);
                if (acct->mlist == NULL) {
                    len += attr_len;
                    break;
                }
                memset(acct->mlist, 0, attr_len + 1);
                memcpy(acct->mlist, &buf[len], attr_len);
                len += attr_len;
            }
            break;

        case TYPE_ROLE_NAME:
            if (attr_len > 0 && acct->sub.rbac_flag) {
                acct->role = AAA_ALLOC(attr_len);
                if (acct->role == NULL) {
                    len += attr_len;
                    break;
                }
                memset(acct->role, 0, attr_len);
                memcpy(acct->role, &buf[len], attr_len);
                len += attr_len;
            } else {
                acct->role = NULL;
            }
            break;

        default:
            break;
        }
    }

    tlv_len += TLV_STR_LEN(&acct->username);
    tlv_len += TLV_STR_LEN(&acct->cui);
    tlv_len += TLV_STR_LEN(&acct->class_attr);
    tlv_len += TLV_STR_LEN(&acct->terminal_type);

    acct->tlv.data = AAA_ALLOC(tlv_len);
    if (acct->tlv.data == NULL) {
        AAA_FREE((char *)acct->iov.data);
        AAA_FREE(acct->role);
        AAA_FREE(acct->mlist);
        AAA_FREE(acct);
        return 0;
    }
    memset(acct->tlv.data, 0, tlv_len);
    acct->tlv.used = tlv_len;
    acct->tlv.left = 0;
    pos = 0;
    aaa_cpy_value(&acct->tlv, &acct->username, &pos);
    aaa_cpy_value(&acct->tlv, &acct->cui, &pos);
    aaa_cpy_value(&acct->tlv, &acct->class_attr, &pos);
    aaa_cpy_value(&acct->tlv, &acct->terminal_type, &pos);

    *acc = acct;
    return 1;
}

/**
 * aaa_parse_result_info - 把接收到的网络字节流buf解析成aaa_result_t结构
 *
 * @result: 存放解析的结果
 * @buf: 要解析的字节流
 * @msg_len: 字节流的长度
 *
 * 把接收到的网络字节流buf解析成aaa_result_t结构，buf是从socket收到的数据，没有msg_type和msg_len
 *
 * 解析失败，返回0；否则返回非0
 */
int aaa_parse_result_info(aaa_result_t **result, char *buf, int msg_len)
{
    int len;
    int pos;
    int tlv_len;
    ushort type;
    ushort attr_len;
    aaa_result_t *res;
    aaa_result_sub_ipc_t *ipc_sub;

    if (buf == NULL || result == NULL) {
        return 0;
    }

    if (msg_len < sizeof(aaa_result_sub_ipc_t)) {
        /* 报文长度非法，解析失败 */
        return 0;
    }

    res = AAA_ALLOC(sizeof(aaa_result_t));
    if (res == NULL) {
        return 0;
    }
    memset(res, 0, sizeof(aaa_result_t));

    len = 0;
    tlv_len = 0;
    /* 接下来都是tlv的数据,T和L都是ushort类型 */
    while (len < msg_len) {
        memcpy((void*)&type, &buf[len], sizeof(ushort));
        len += sizeof(ushort);

        memcpy((void*)&attr_len, &buf[len], sizeof(ushort));
        len += sizeof(ushort);

        switch (type) {
        case TYPE_SUB_STRUCT:
            if (attr_len == sizeof(aaa_result_sub_ipc_t)) {
                ipc_sub = (aaa_result_sub_ipc_t *)&buf[len];
                aaa_parse_result_info_sub(&res->sub, ipc_sub);
            }
            len += attr_len;
            break;
        case TYPE_USERNAME:
            aaa_cpy_tlv(&res->username, type, attr_len, buf, &len);
            break;            
        case TYPE_EAP_MSG:
            aaa_cpy_tlv(&res->eap_msg, type, attr_len, buf, &len);
            break;
        case TYPE_UNKNOWN:
            aaa_cpy_tlv(&res->unknown, type, attr_len, buf, &len);
            break;
        case TYPE_CLASS_ATTR:
            aaa_cpy_tlv(&res->class_attr, type, attr_len, buf, &len);
            break;
        case TYPE_REPLY_MSG:
            aaa_cpy_tlv(&res->reply_msg, type, attr_len, buf, &len);
            break;
        case TYPE_STATE:
            aaa_cpy_tlv(&res->state, type, attr_len, buf, &len);
            break;
        case TYPE_CUI:
            aaa_cpy_tlv(&res->cui, type, attr_len, buf, &len);
            break;
        case TYPE_MSCHAP_RESP:
            aaa_cpy_tlv(&res->mschap_resp, type, attr_len, buf, &len);
            break;
        case TYPE_MPPE_SEND_KEY:
            res->mppe_key.send_key_len = attr_len;
            if (attr_len > 0) {
                res->mppe_key.send_key = AAA_ALLOC(attr_len + 1);
                if (res->mppe_key.send_key == NULL) {
                    len += attr_len;
                    break;
                }
                memset(res->mppe_key.send_key, 0, attr_len + 1);
                memcpy(res->mppe_key.send_key, &buf[len], attr_len);
                len += attr_len;
            }
            break;
        case TYPE_MPPE_RECV_KEY:
            res->mppe_key.recv_key_len = attr_len;
            if (attr_len > 0) {
                res->mppe_key.recv_key = AAA_ALLOC(attr_len + 1);
                if (res->mppe_key.recv_key == NULL) {
                    len += attr_len;
                    break;
                }
                memset(res->mppe_key.recv_key, 0, attr_len + 1);
                memcpy(res->mppe_key.recv_key, &buf[len], attr_len);
                len += attr_len;
            }
            break;
        case TYPE_UDATA:
            if (attr_len > 0) {
                res->udata = AAA_ALLOC(attr_len);
                if (res->udata == NULL) {
                    len += attr_len;
                    break;
                }
                memset(res->udata, 0, attr_len);
                memcpy(res->udata, &buf[len], attr_len);
                len += attr_len;
            }
            break;
        case TYPE_IOV_DATA:
            if (attr_len > 0) {
                res->iov.data = AAA_ALLOC(attr_len + 1);
                if (res->iov.data == NULL) {
                    len += attr_len;
                    break;
                }
                memset(res->iov.data, 0, attr_len + 1);
                memcpy(res->iov.data, &buf[len], attr_len);
                len += attr_len;
                res->iov.used += attr_len;
                res->iov.left = 0;
            }
            break;
        case TYPE_ROLE_NAME:
            if (attr_len > 0 && res->sub.rbac_flag) {
                res->role = AAA_ALLOC(attr_len);
                if (res->role == NULL) {
                    len += attr_len;
                    break;
                }
                memset(res->role, 0, attr_len);
                memcpy(res->role, &buf[len], attr_len);
                len += attr_len;
            }
            break;
        default:
            len += attr_len;
            break;
        }
    }

    tlv_len += TLV_STR_LEN(&res->username);
    tlv_len += TLV_STR_LEN(&res->eap_msg);
    tlv_len += TLV_STR_LEN(&res->unknown);
    tlv_len += TLV_STR_LEN(&res->class_attr);
    tlv_len += TLV_STR_LEN(&res->reply_msg);
    tlv_len += TLV_STR_LEN(&res->state);
    tlv_len += TLV_STR_LEN(&res->cui);
    tlv_len += TLV_STR_LEN(&res->mschap_resp);

    res->tlv.data = AAA_ALLOC(tlv_len);
    if (res->tlv.data == NULL) {
        AAA_FREE((char *)res->iov.data);
        AAA_FREE(res->udata);
        AAA_FREE(res->role);
        AAA_FREE(res->mppe_key.send_key);
        AAA_FREE(res->mppe_key.recv_key);
        AAA_FREE(res);
        return 0;
    }
    memset(res->tlv.data, 0, tlv_len);
    res->tlv.used = tlv_len;
    res->tlv.left = 0;

    pos = 0;
    aaa_cpy_value(&res->tlv, &res->username, &pos);    
    aaa_cpy_value(&res->tlv, &res->eap_msg, &pos);
    aaa_cpy_value(&res->tlv, &res->unknown, &pos);
    aaa_cpy_value(&res->tlv, &res->class_attr, &pos);
    aaa_cpy_value(&res->tlv, &res->reply_msg, &pos);
    aaa_cpy_value(&res->tlv, &res->state, &pos);
    aaa_cpy_value(&res->tlv, &res->cui, &pos);
    aaa_cpy_value(&res->tlv, &res->mschap_resp, &pos);

    *result = res;
    return 1;
}

/**
 * aaa_free_authen_info - 释放authen所指的内存
 *
 * @authen: 要释放内存的指针
 *
 * 释放authen所指的内存
 *
 */
void aaa_free_authen_info(authen_info_t *authen)
{
    if (authen == NULL) {
        return;
    }

    if (authen->role != NULL) {
        AAA_FREE(authen->role);
    }

    if (authen->tlv.data != NULL) {
        AAA_FREE(authen->tlv.data);
    }

    if (authen->iov.data != NULL) {
        AAA_FREE(authen->iov.data);
    }

    if (authen->udata != NULL) {
        AAA_FREE(authen->udata);
    }

    if (authen->mlist != NULL) {
        AAA_FREE(authen->mlist);
    }

    AAA_FREE(authen);
}

/**
 * aaa_free_author_info - 释放author所指的内存
 *
 * @author: 要释放内存的指针
 *
 * 释放author所指的内存
 *
 */
void aaa_free_author_info(author_info_t *author)
{
    if (author == NULL) {
        return;
    }

    if (author->tlv.data != NULL) {
        AAA_FREE(author->tlv.data);
    }

    if (author->iov.data != NULL) {
        AAA_FREE(author->iov.data);
    }

    if (author->mlist) {
        AAA_FREE(author->mlist);
    }

    AAA_FREE(author);
}

/**
 * aaa_free_acct_info - 释放acct所指的内存
 *
 * @acct: 要释放内存的指针
 *
 * 释放acct所指的内存
 *
 */
void aaa_free_acct_info(acct_info_t *acct)
{
    if (acct == NULL) {
        return;
    }

    if (acct->tlv.data != NULL) {
        AAA_FREE(acct->tlv.data);
    }

    if (acct->iov.data != NULL) {
        AAA_FREE(acct->iov.data);
    }

    if (acct->mlist) {
        AAA_FREE(acct->mlist);
    }

    if (acct->role) {
        AAA_FREE(acct->role);
    }

    AAA_FREE(acct);
}

/**
 * aaa_free_result_info - 释放res所指的内存
 *
 * @res: 要释放内存的指针
 *
 * 释放res所指的内存
 *
 */
void aaa_free_result_info(aaa_result_t *res)
{
    if (res == NULL) {
        return;
    }

    if (res->role != NULL) {
        AAA_FREE(res->role);
    }

    if (res->udata != NULL) {
        AAA_FREE(res->udata);
    }

    if (res->mppe_key.recv_key != NULL) {
        AAA_FREE(res->mppe_key.recv_key);
    }

    if (res->mppe_key.send_key != NULL) {
        AAA_FREE(res->mppe_key.send_key);
    }

    if (res->tlv.data != NULL) {
        AAA_FREE(res->tlv.data);
    }

    if (res->iov.data != NULL) {
        AAA_FREE(res->iov.data);
    }

    AAA_FREE(res);
}

int aaa_make_path(char *dir_buf, char *path_suffix, int buf_len)
{       
    char *path_prefix;

    path_prefix = getenv(AAA_TMP_DIR);
    if (path_prefix == NULL) {         
        return 0;
    }
    if (strlen(path_prefix) + strlen(path_suffix) >= buf_len) {
        return 0;
    }
    strcpy(dir_buf, path_prefix);    
    strcat(dir_buf, path_suffix);    
    return 1;
}

static unsigned long time_interval(unsigned long t1, unsigned long t2)
{
    long interval = (long) t1 - (long) t2;
    return ((unsigned long) labs(interval));
}

int aaa_reg_ham_client_thread_notify(pid_t pid, unsigned int tid)
{
    return ham_client_reg_thread_notify(pid, tid,
               AAA_HAM_FAULT_DETECT_PERIOD_S, AAA_HAM_FAULT_DETECT_TIME);
}

int aaa_dereg_ham_client_notify(void)
{
    int ret;
    ret = ham_client_unreg_thread_notify(syscall(SYS_gettid));
    
    return ret;
}

int aaa_dereg_ham_client_notify_by_tid(pthread_t tid)
{
    int ret;
    ret = ham_client_unreg_thread_notify(tid);
    
    return ret;
}

int aaa_reg_ham_client_notify(void)
{
    return ham_client_reg_thread_notify(getpid(), syscall(SYS_gettid),
               AAA_HAM_FAULT_DETECT_PERIOD_S, AAA_HAM_FAULT_DETECT_TIME);
}

int aaa_reset_ham_client_notify(void)
{
    return ham_client_reset_thread_notify(getpid(), syscall(SYS_gettid),
               AAA_HAM_FAULT_DETECT_PERIOD_S, AAA_HAM_FAULT_DETECT_TIME);
}

void aaa_check_reset_ham_client_notify(long *feed_tm)
{
    long cur_tm;
    struct timeval sys_time;

    sys_time = rg_monotime();
    cur_tm = rg_timeval_to_sec(sys_time);

    /* 防止短时间内频繁喂 */
    if (time_interval((unsigned long)cur_tm, (unsigned long)(*feed_tm)) > AAA_HAM_FEED_TIME_INTERVAL_S) {
        if (aaa_reset_ham_client_notify() >= 0) {
           *feed_tm = cur_tm;
        }
    }

    return;
}

int aaa_file_lock(int fd)
{
    struct flock fl;

    memset(&fl, 0, sizeof(fl));
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0;

    if (fcntl(fd, F_SETLKW, &fl) != 0) {
        return -1;
    }
    return 0;
}

int aaa_file_unlock(int fd)
{
    struct flock fl;

    memset(&fl, 0, sizeof(fl));
    fl.l_type = F_UNLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0;

    if (fcntl(fd, F_SETLKW, &fl) != 0) {
        return -1;
    }
    return 0;
}
