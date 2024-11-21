tc filter del dev ens4 egress
tc qdisc del dev ens4 clsact

rm /sys/fs/bpf/bmc_tx_filter
