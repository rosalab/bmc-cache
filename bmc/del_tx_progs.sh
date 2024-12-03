tc filter del dev enp0s4 egress
tc qdisc del dev enp0s4 clsact

rm /sys/fs/bpf/bmc_tx_filter
