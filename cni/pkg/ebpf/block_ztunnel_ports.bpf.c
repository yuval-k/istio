// clang-format off
#include "vmlinux.h"
// clang-format on

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>


#define AF_INET 2
#define AF_INET6 10

volatile const __u32 ztunnel_mark = 3;
volatile const __u16 ztunnel_outbound_port = 15001;
volatile const __u16 ztunnel_inbound_port = 15008;
volatile const __u16 ztunnel_inbound_plain_port = 15006;
volatile const __u16 ztunnel_dns_port = 15053;

static __always_inline int bind_prog(struct bpf_sock_addr *ctx, int family) {
  struct bpf_sock *sk;
  __u32 port;
  __u32 mark;

  sk = ctx->sk;
  if (!sk) return 1;

  if (sk->family != family) return 1;

  port = bpf_ntohs(ctx->user_port);
  mark = sk->mark;
  if (ctx->type == SOCK_STREAM) {
    if ((port == ztunnel_outbound_port) || (port == ztunnel_inbound_port) ||
        (port == ztunnel_inbound_plain_port)) {
      if ((mark & ztunnel_mark) == ztunnel_mark) {
        return 1;
      }
      return 0;
    }
  } else if (ctx->type == SOCK_DGRAM) {
    if (port == ztunnel_dns_port) {
      if ((mark & ztunnel_mark) == ztunnel_mark) {
        return 1;
      }
      return 0;
    }
  }

  return 1;
}

SEC("cgroup/bind4")
int bind_v4_prog(struct bpf_sock_addr *ctx) { return bind_prog(ctx, AF_INET); }

SEC("cgroup/bind6")
int bind_v6_prog(struct bpf_sock_addr *ctx) { return bind_prog(ctx, AF_INET6); }

// char _license[] SEC("license") = "GPL";
