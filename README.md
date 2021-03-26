    # canTrace
    This tool is a debug tracer for CAN messages based on eBPF. Currently it supports display of transmit, receive count for each CAN node which is created by 'ip link set' command. Works for CAN, CAN-FD messages as well. 

    This program has been tested with Ubuntu with linux kernel 4.15.x
    
    can_ebpf_trace  tracepoints net_dev_xmit, netif_receive_skb calls and monitors the device of type to be canX. For each matching can device  with names can0, can1, etc. bpf map is created with rx, tx counts and this is exchanged between user space and kernel space modules. For creating socketcan based devices, use ip link set commands. Refer to https://www.kernel.org/doc/Documentation/networking/can.txt

    Compliling and running the program
    
    # make
    # ./can_ebpf_trace
       eBPF based Can Bus Trace - Statistics
       ControllerName: Tx/Rx count
       CAN1 = 100 / 200  CAN0 = 100 / 200
    # run cansend or any other tools which invokes socketcan based read/write messages.

eBPF approach & next steps
====================================
eBPF approach can be considered in general all features of CAN tracing. eBPS maps act as key design element to exchange the data from kernel to the user space applications. Suggestions are open to extend the tool for all monitoring use cases. 

 eBPF info
=====================================================
 
[1] https://lwn.net/Articles/437884/
[2] https://www.kernel.org/doc/Documentation/networking/filter.txt



