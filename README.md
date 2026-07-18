# eBPF Network Monitor

> A kernel module that provides in-depth insights into network activity using eBPF.

## Overview

The eBPF Network Monitor is a kernel module that utilizes eBPF to monitor network activity, providing valuable insights into packet flow and network metrics. This project addresses the need for a lightweight and efficient network monitoring solution that can be easily integrated into existing systems. By leveraging the power of eBPF, this module offers a unique perspective on network behavior, enabling administrators to identify potential bottlenecks, troubleshoot issues, and optimize network performance.

## Features

- **Real-time Packet Capture**: Capture and analyze network packets in real-time, providing detailed information on packet flow and network activity.
- **Network Metrics**: Collect and display key network metrics, including packet counts, byte counts, and latency measurements.
- **Customizable Filtering**: Configure filtering rules to focus on specific network traffic, such as by protocol, port, or IP address.
- **User-space Tooling**: Utilize a user-space tool to interact with the eBPF program, enabling easy configuration and data visualization.
- **Kernel Module**: Load the eBPF program as a kernel module, providing seamless integration with the kernel and efficient performance.
- **Extensive Documentation**: Detailed documentation and API references for easy integration and customization.
- **Highly Scalable**: Designed to handle high network traffic rates and large-scale networks.
- **Easy Installation**: Simple installation process using standard kernel module loading tools.

## Getting Started

### Prerequisites

- Linux kernel 4.15 or later
- eBPF support enabled in the kernel
- GCC compiler version 9 or later
- Make tool version 4.2 or later

### Installation

```bash
# Clone the repository
git clone https://github.com/your-username/ebpf-network-monitor.git

# Build the kernel module
make -C /lib/modules/$(uname -r)/build M=$(pwd) modules

# Load the kernel module
sudo insmod nethook.ko

# Activate the eBPF program
sudo echo "attach { /sys/fs/bpf/nethook }" > /sys/fs/bpf/nethook/attach
```

### Usage

```bash
# View network metrics
sudo cat /sys/fs/bpf/nethook/metrics

# View packet capture data
sudo cat /sys/fs/bpf/nethook/packets

# Configure filtering rules
sudo echo "filter { /sys/fs/bpf/nethook/filter }" > /sys/fs/bpf/nethook/filter
```

## Architecture

The eBPF Network Monitor consists of three primary components:

*   **src/bpf/nethook.c**: The eBPF program handling network hook, which captures network packets and collects metrics.
*   **src/kmod/nethook.ko**: The kernel module for loading the eBPF program, providing seamless integration with the kernel.
*   **src/user/nethook.c**: The user-space tool for interacting with the eBPF program, enabling easy configuration and data visualization.

## API Reference

The eBPF Network Monitor provides the following public interfaces:

*   **/sys/fs/bpf/nethook/attach**: Attach the eBPF program to the network hook.
*   **/sys/fs/bpf/nethook/filter**: Configure filtering rules for packet capture.
*   **/sys/fs/bpf/nethook/metrics**: View network metrics.
*   **/sys/fs/bpf/nethook/packets**: View packet capture data.

## Testing

```bash
# Run unit tests
make -C /lib/modules/$(uname -r)/build M=$(pwd) clean
make -C /lib/modules/$(uname -r)/build M=$(pwd) tests

# Run integration tests
sudo insmod nethook.ko
sudo echo "attach { /sys/fs/bpf/nethook }" > /sys/fs/bpf/nethook/attach
sudo cat /sys/fs/bpf/nethook/metrics
```

## Contributing

1.  Fork the repository
2.  Create a feature branch
3.  Commit changes
4.  Push and open a PR

## License

MIT License