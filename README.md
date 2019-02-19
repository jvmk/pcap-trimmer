# pcap-trimmer

## Summary
`pcap-trimmer` is a tool for filtering network traces in `.pcap` format. It serves as an alternative to `tshark` for those users who are more comfortable working in Java, or whose filter needs are more complex than what is possible to specify as a BPF expression. Given an input `.pcap` file, `inputPcap`, produces an output `.pcap` file, `outputPcap`, which only contains those packets in `inputPcap` that pass through a user specified filter, `filterImplementation`. The tool builds on top of [`pcap4j`](https://github.com/kaitoy/pcap4j) and therefore assumes that `pcap4j`'s dependencies are present on the platform (e.g., that a native pcap library is installed).

## Usage directions
Usage:
```
./gradlew run --args="'inputPcap' 'outputPcap' 'filterImplementation' 'filterImplementationFullClassName'"
```
where:
1. `'inputPcap'` is the path to the original `.pcap` file for which a filtered `.pcap` is desired.
2. `'outputPcap'`is the path to the file that is to store the filtered network trace.
3. `'filterImplementation'` is a Java class that implements `java.util.function.Function<org.pcap4j.core.PcapPacket, java.lang.Boolean>`. This is where you specify your logic that decides if a packet is to be included in the filtered network trace. You may specify either a `.java` or a `.class` file. If a `.java` file is specified, `pcap-trimmer` will compile the source file and output the corresponding `.class` file in the source file's directory.
4. `'filterImplementationFullClassName'` is the fully qualified name of `filterImplementation`.

### Example usage
Suppose you wish to extract a subtrace of `/home/username/in.pcap` that only contains UDP packets. First, specify an implementation of `java.util.function.Function<org.pcap4j.core.PcapPacket, java.lang.Boolean>` where `apply(PcapPacket)` only returns `true` if the given `PcapPacket` is a UDP packet:
```
package com.example;

import org.pcap4j.core.PcapPacket;
import org.pcap4j.packet.UdpPacket;
import java.util.function.Function;

public class UdpFilter implements Function<PcapPacket, Boolean> {

    @Override
    public Boolean apply(PcapPacket pkt) {
        return pkt.get(UdpPacket.class) != null;
    }

}
```
Suppose that the source code for the `UdpFilter` class shown above resides in the file `/home/username/UdpFilter.java`, and  that you want to output the filtered trace to the file `/home/username/udp.pcap`, then invoke `pcap-trimmer` as follows:
```
./gradlew run --args="'/home/username/in.pcap' '/home/username/udp.pcap' '/home/username/UdpFilter.java' 'com.example.UdpFilter'"
```
