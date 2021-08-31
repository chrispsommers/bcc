#!/usr/bin/python3

import sys
import time

from bcc import BPF

src = r"""
#include <linux/netlink.h>

BPF_PERF_OUTPUT(netlink);

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


    netlink.perf_submit(ctx, &event, sizeof(event));

    return 0;
}
"""

b = BPF(text=src)

def callback(ctx, data, size):
    event = b['netlink'].event(data)
    print("%6d %6d %6d %-12s %4d 0x%-8x %12d 0x%-8x 0x%-8x" % \
        (event.pid_tid>>32, event.pid_tid&0xffffffff, event.nlmsg_type, "ROUTE", \
        event.nlmsg_len, event.nlmsg_flags, event.nlmsg_seq, event.nlmsg_pid, event.portid))

b['netlink'].open_perf_buffer(callback)

print("Printing netlink() calls, ctrl-c to exit...\n")

print("%-6s %-6s %-6s %-12s %-4s %-10s %-12s %-10s %-10s" % ("PID", "TID", "TYPE", "TYPE-descr", "LEN", "FLAGS", "SEQ", "NL PID", "PORTID"))
print("%-6s %-6s %-6s %-12s %-4s %-10s %-12s %-10s %-10s" % ("======", "======", "======", "============", "====", "==========", "============", "==========", "=========="))

try:
    while 1:
        b.perf_buffer_poll()
        # or b.ring_buffer_consume()
        time.sleep(0.1)
except KeyboardInterrupt:
    sys.exit()
