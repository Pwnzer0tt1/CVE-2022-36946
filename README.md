# CVE-2022-36946

Reported-by: Domingo Dirutigliano and Nicola Guerrera

While we were working on [firegex](https://github.com/Pwnzer0tt1/firegex), our application firewall for CTF Attack-Defence competitions, we stumbled upon a few kernel panics. 

This strange behavour was than isolated and anlayzed, leading to the dicovery of this potential security flaw in the netfilter module, specifically with nfnetlink.

# How does it work?

The kernel panics when sending nf\_queue verdict with 0-byte nfta\_payload attribute.

```
nlh = nfq_nlmsg_put(buf, NFQNL_MSG_VERDICT, queue_num);
nfq_nlmsg_verdict_put_pkt(nlh, NULL, 0);
nfq_nlmsg_verdict_put(nlh, 1, NF_ACCEPT );
```

This happens because the IP/IPv6 stack pulls the IP(v6) header from the packet after the input hook.

So, if user truncates the packet below the header size, this skb\_pull() will result in a malformed skb resulting in a panic. 

Try it executing [this](/panic6.c) c source code.

# Fix up

Fixed in linux kernel 5.19 [view diff](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/diff/net/netfilter/nfnetlink_queue.c?id=v5.19&id2=v5.18)

Original patch by the linux kernel security team [here](https://marc.info/?l=netfilter-devel&m=165883202007292&w=2)

# Requirements for exploiting this vuln:

- A vulnerable linux kernel
- CAP\_NET\_ADMIN capability


# Why panic6?

It worked at the 6th attempt, so we kept the name.
