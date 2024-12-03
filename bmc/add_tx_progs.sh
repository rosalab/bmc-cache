tc qdisc add dev enp0s4 clsact
tc filter add dev enp0s4 egress bpf object-pinned /sys/fs/bpf/bmc_tx_filter
