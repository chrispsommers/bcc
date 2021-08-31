#!/usr/bin/python3

import sys
import time

from bcc import BPF

src = r"""
#include <linux/netlink.h>
BPF_RINGBUF_OUTPUT(netlink, 1 << 4);

struct event {
        u32           pid_tid;        /* (pid<<32 | tid) of current process */
        u32           portid;         /* portid of receiving process */
        u32           nlmsg_len;      /* Length of message including header */
        u16           nlmsg_type;     /* Message content */
        u16           nlmsg_flags;    /* Additional flags */
        u32           nlmsg_seq;      /* Sequence number */
        u32           nlmsg_pid;      /* Sending process port ID */
};

int kprobe__netlink_unicast(struct pt_regs *ctx, struct sock *ssk, struct sk_buff *skb, __u32 portid, int nonblock) {

    struct event event = {};

    struct nlmsghdr * nm_nlh_skb = (struct nlmsghdr *)(skb->data);
    event.pid_tid = bpf_get_current_pid_tgid();
    event.portid = portid;
    event.nlmsg_len = nm_nlh_skb->nlmsg_len;
    event.nlmsg_type = nm_nlh_skb->nlmsg_type;
    event.nlmsg_flags = nm_nlh_skb->nlmsg_flags;
    event.nlmsg_seq = nm_nlh_skb->nlmsg_seq;
    event.nlmsg_pid = nm_nlh_skb->nlmsg_pid;
    int rc = 0;
	rc=bpf_trace_printk("len=%d type=%d flags=0x%x...\n",
                     event.nlmsg_len, event.nlmsg_type, event.nlmsg_flags);
	bpf_trace_printk("  ...seq=%d pid=%d portid=0x%x\n",
                      event.nlmsg_seq, event.nlmsg_pid, event.portid);


    netlink.ringbuf_output(&event, sizeof(event), 0);

    return 0;
}
"""

b = BPF(text=src)

def netlink_type_str(type):
    '''
    Netlink Type -> string map. Take constants from .h files and convert to dict to display types by name
    Can use editor e.g. VScode to convert #defines into this map, e.g. select regex replace with these:
    search pattern:  #define (NETLINK[^ \t]*)[ \t]*([0-9]*).*$
    replace pattern: \t\t$2:'$1',
    Plus a little manual fix-up.
    TODO - explore https://pypi.org/project/libnl3/
    '''
    netlink_types = {
        # From src/cc/libbpf/include/uapi/linux/netlink.h
        0:'NETLINK_ROUTE',
        1:'NETLINK_UNUSED',
        2:'NETLINK_USERSOCK',
        3:'NETLINK_FIREWALL',
        4:'NETLINK_SOCK_DIAG',
        5:'NETLINK_NFLOG',
        6:'NETLINK_XFRM',
        7:'NETLINK_SELINUX',
        8:'NETLINK_ISCSI',
        9:'NETLINK_AUDIT',
        10:'NETLINK_FIB_LOOKUP',
        11:'NETLINK_CONNECTOR',
        12:'NETLINK_NETFILTER',
        13:'NETLINK_IP6_FW',
        14:'NETLINK_DNRTMSG',
        15:'NETLINK_KOBJECT_UEVENT',
        16:'NETLINK_GENERIC',
        18:'NETLINK_SCSITRANSPORT',
        19:'NETLINK_ECRYPTFS',
        20:'NETLINK_RDMA',
        21:'NETLINK_CRYPTO',
        22:'NETLINK_SMC',
        # From https://github.com/linux-audit/audit-userspace/blob/master/lib/libaudit.h
		1100:'AUDIT_FIRST_USER_MSG',
		1199:'AUDIT_LAST_USER_MSG',
		1100:'AUDIT_USER_AUTH',
		1101:'AUDIT_USER_ACCT',
		1102:'AUDIT_USER_MGMT',
		1103:'AUDIT_CRED_ACQ',
		1104:'AUDIT_CRED_DISP',
		1105:'AUDIT_USER_START',
		1106:'AUDIT_USER_END',
		1107:'AUDIT_USER_AVC',
		1108:'AUDIT_USER_CHAUTHTOK',
		1109:'AUDIT_USER_ERR',
		1110:'AUDIT_CRED_REFR',
		1111:'AUDIT_USYS_CONFIG',
		1112:'AUDIT_USER_LOGIN',
		1113:'AUDIT_USER_LOGOUT',
		1114:'AUDIT_ADD_USER',
		1115:'AUDIT_DEL_USER',
		1116:'AUDIT_ADD_GROUP',
		1117:'AUDIT_DEL_GROUP',
		1118:'AUDIT_DAC_CHECK',
		1119:'AUDIT_CHGRP_ID',
		1120:'AUDIT_TEST',
		1121:'AUDIT_TRUSTED_APP',
		1122:'AUDIT_USER_SELINUX_ERR',
		1123:'AUDIT_USER_CMD',
		1124:'AUDIT_USER_TTY',
		1125:'AUDIT_CHUSER_ID',
		1126:'AUDIT_GRP_AUTH',
		1127:'AUDIT_SYSTEM_BOOT',
		1128:'AUDIT_SYSTEM_SHUTDOWN',
		1129:'AUDIT_SYSTEM_RUNLEVEL',
		1130:'AUDIT_SERVICE_START',
		1131:'AUDIT_SERVICE_STOP',
		1132:'AUDIT_GRP_MGMT',
		1133:'AUDIT_GRP_CHAUTHTOK',
		1134:'AUDIT_MAC_CHECK',
		1135:'AUDIT_ACCT_LOCK',
		1136:'AUDIT_ACCT_UNLOCK',
		1137:'AUDIT_USER_DEVICE',
		1138:'AUDIT_SOFTWARE_UPDATE',
		1200:'AUDIT_FIRST_DAEMON',
		1299:'AUDIT_LAST_DAEMON',
		1204:'AUDIT_DAEMON_RECONFIG',
		1205:'AUDIT_DAEMON_ROTATE',
		1206:'AUDIT_DAEMON_RESUME',
		1207:'AUDIT_DAEMON_ACCEPT',
		1208:'AUDIT_DAEMON_CLOSE',
		1209:'AUDIT_DAEMON_ERR',
		1300:'AUDIT_FIRST_EVENT',
		1399:'AUDIT_LAST_EVENT',
		1400:'AUDIT_FIRST_SELINUX',
		1499:'AUDIT_LAST_SELINUX',
		1500:'AUDIT_FIRST_APPARMOR',
		1599:'AUDIT_LAST_APPARMOR',
		1500:'AUDIT_AA',
		1501:'AUDIT_APPARMOR_AUDIT',
		1502:'AUDIT_APPARMOR_ALLOWED',
		1503:'AUDIT_APPARMOR_DENIED',
		1504:'AUDIT_APPARMOR_HINT',
		1505:'AUDIT_APPARMOR_STATUS',
		1506:'AUDIT_APPARMOR_ERROR',
		1507:'AUDIT_APPARMOR_KILL',
		1600:'AUDIT_FIRST_KERN_CRYPTO_MSG',
		1699:'AUDIT_LAST_KERN_CRYPTO_MSG',
		1700:'AUDIT_FIRST_KERN_ANOM_MSG',
		1799:'AUDIT_LAST_KERN_ANOM_MSG',
		1800:'AUDIT_INTEGRITY_FIRST_MSG',
		1899:'AUDIT_INTEGRITY_LAST_MSG',
		1800:'AUDIT_INTEGRITY_DATA',
		1801:'AUDIT_INTEGRITY_METADATA',
		1802:'AUDIT_INTEGRITY_STATUS',
		1803:'AUDIT_INTEGRITY_HASH',
		1804:'AUDIT_INTEGRITY_PCR',
		1805:'AUDIT_INTEGRITY_RULE',
		1806:'AUDIT_INTEGRITY_EVM_XATTR',
		1807:'AUDIT_INTEGRITY_POLICY_RULE',
		2100:'AUDIT_FIRST_ANOM_MSG',
		2199:'AUDIT_LAST_ANOM_MSG',
		2100:'AUDIT_ANOM_LOGIN_FAILURES',
		2101:'AUDIT_ANOM_LOGIN_TIME',
		2102:'AUDIT_ANOM_LOGIN_SESSIONS',
		2103:'AUDIT_ANOM_LOGIN_ACCT',
		2104:'AUDIT_ANOM_LOGIN_LOCATION',
		2105:'AUDIT_ANOM_MAX_DAC',
		2106:'AUDIT_ANOM_MAX_MAC',
		2107:'AUDIT_ANOM_AMTU_FAIL',
		2108:'AUDIT_ANOM_RBAC_FAIL',
		2109:'AUDIT_ANOM_RBAC_INTEGRITY_FAIL',
		2110:'AUDIT_ANOM_CRYPTO_FAIL',
		2111:'AUDIT_ANOM_ACCESS_FS',
		2112:'AUDIT_ANOM_EXEC',
		2113:'AUDIT_ANOM_MK_EXEC',
		2114:'AUDIT_ANOM_ADD_ACCT',
		2115:'AUDIT_ANOM_DEL_ACCT',
		2116:'AUDIT_ANOM_MOD_ACCT',
		2117:'AUDIT_ANOM_ROOT_TRANS',
		2118:'AUDIT_ANOM_LOGIN_SERVICE',
		2119:'AUDIT_ANOM_LOGIN_ROOT',
		2120:'AUDIT_ANOM_ORIGIN_FAILURES',
		2121:'AUDIT_ANOM_SESSION',
		2200:'AUDIT_FIRST_ANOM_RESP',
		2299:'AUDIT_LAST_ANOM_RESP',
		2200:'AUDIT_RESP_ANOMALY',
		2201:'AUDIT_RESP_ALERT',
		2202:'AUDIT_RESP_KILL_PROC',
		2203:'AUDIT_RESP_TERM_ACCESS',
		2204:'AUDIT_RESP_ACCT_REMOTE',
		2205:'AUDIT_RESP_ACCT_LOCK_TIMED',
		2206:'AUDIT_RESP_ACCT_UNLOCK_TIMED',
		2207:'AUDIT_RESP_ACCT_LOCK',
		2208:'AUDIT_RESP_TERM_LOCK',
		2209:'AUDIT_RESP_SEBOOL',
		2210:'AUDIT_RESP_EXEC',
		2211:'AUDIT_RESP_SINGLE',
		2212:'AUDIT_RESP_HALT',
		2213:'AUDIT_RESP_ORIGIN_BLOCK',
		2214:'AUDIT_RESP_ORIGIN_BLOCK_TIMED',
		2215:'AUDIT_RESP_ORIGIN_UNBLOCK_TIMED',
		2300:'AUDIT_FIRST_USER_LSPP_MSG',
		2399:'AUDIT_LAST_USER_LSPP_MSG',
		2300:'AUDIT_USER_ROLE_CHANGE',
		2301:'AUDIT_ROLE_ASSIGN',
		2302:'AUDIT_ROLE_REMOVE',
		2303:'AUDIT_LABEL_OVERRIDE',
		2304:'AUDIT_LABEL_LEVEL_CHANGE',
		2305:'AUDIT_USER_LABELED_EXPORT',
		2306:'AUDIT_USER_UNLABELED_EXPORT',
		2307:'AUDIT_DEV_ALLOC',
		2308:'AUDIT_DEV_DEALLOC',
		2309:'AUDIT_FS_RELABEL',
		2310:'AUDIT_USER_MAC_POLICY_LOAD',
		2311:'AUDIT_ROLE_MODIFY',
		2312:'AUDIT_USER_MAC_CONFIG_CHANGE',
		2313:'AUDIT_USER_MAC_STATUS',
		2400:'AUDIT_FIRST_CRYPTO_MSG',
		2400:'AUDIT_CRYPTO_TEST_USER',
		2401:'AUDIT_CRYPTO_PARAM_CHANGE_USER',
		2402:'AUDIT_CRYPTO_LOGIN',
		2403:'AUDIT_CRYPTO_LOGOUT',
		2404:'AUDIT_CRYPTO_KEY_USER',
		2405:'AUDIT_CRYPTO_FAILURE_USER',
		2406:'AUDIT_CRYPTO_REPLAY_USER',
		2407:'AUDIT_CRYPTO_SESSION',
		2408:'AUDIT_CRYPTO_IKE_SA',
		2409:'AUDIT_CRYPTO_IPSEC_SA',
		2499:'AUDIT_LAST_CRYPTO_MSG',
		2500:'AUDIT_FIRST_VIRT_MSG',
		2500:'AUDIT_VIRT_CONTROL',
		2501:'AUDIT_VIRT_RESOURCE',
		2502:'AUDIT_VIRT_MACHINE_ID',
		2503:'AUDIT_VIRT_INTEGRITY_CHECK',
		2504:'AUDIT_VIRT_CREATE',
		2505:'AUDIT_VIRT_DESTROY',
		2506:'AUDIT_VIRT_MIGRATE_IN',
		2507:'AUDIT_VIRT_MIGRATE_OUT',
		2599:'AUDIT_LAST_VIRT_MSG',
		2100:'AUDIT_FIRST_USER_MSG2',
		2999:'AUDIT_LAST_USER_MSG2',
		1018:'AUDIT_SET_FEATURE',
		1019:'AUDIT_GET_FEATURE',
		1323:'AUDIT_MMAP',
		1324:'AUDIT_NETFILTER_PKT',
		1325:'AUDIT_NETFILTER_CFG',
		1326:'AUDIT_SECCOMP',
		1327:'AUDIT_PROCTITLE',
		1328:'AUDIT_FEATURE_CHANGE',
		1329:'AUDIT_REPLACE',
		1330:'AUDIT_KERN_MODULE',
		1331:'AUDIT_FANOTIFY',
		1332:'AUDIT_TIME_INJOFFSET',
		1333:'AUDIT_TIME_ADJNTPVAL',
		1334:'AUDIT_BPF',
		1335:'AUDIT_EVENT_LISTENER',
		1418:'AUDIT_MAC_CALIPSO_ADD',
		1419:'AUDIT_MAC_CALIPSO_DEL',
		1702:'AUDIT_ANOM_LINK',
		1703:'AUDIT_ANOM_CREAT'
    }

    if type in netlink_types:
        return netlink_types[type]
    else:
        return 'UNKNOWN'

def callback(ctx, data, size):
    event = b['netlink'].event(data)
    print("%6d %6d %6d %-12s %4d 0x%-8x %12d 0x%-8x 0x%-8x" % \
        (event.pid_tid>>32, event.pid_tid&0xffffffff, event.nlmsg_type, netlink_type_str(event.nlmsg_type), \
        event.nlmsg_len, event.nlmsg_flags, event.nlmsg_seq, event.nlmsg_pid, event.portid))

b['netlink'].open_ring_buffer(callback)

print("Printing netlink() calls, ctrl-c to exit...\n")

print("%-6s %-6s %-6s %-12s %-4s %-10s %-12s %-10s %-10s" % ("PID", "TID", "TYPE", "TYPE-descr", "LEN", "FLAGS", "SEQ", "NL PID", "PORTID"))
print("%-6s %-6s %-6s %-12s %-4s %-10s %-12s %-10s %-10s" % ("======", "======", "======", "============", "====", "==========", "============", "==========", "=========="))

try:
    while 1:
        b.ring_buffer_poll()
        # or b.ring_buffer_consume()
        time.sleep(0.1)
except KeyboardInterrupt:
    sys.exit()
