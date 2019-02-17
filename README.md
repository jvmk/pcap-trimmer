# pcap-trimmer
Given an input `.pcap` file, `inputPcap`, produces an output `.pcap` file, `outputPcap`, which only contains those packets in `inputPcap` that pass through a user specified filter, `filterImplementation`.

Usage: `./gradlew run --args="'inputPcap' 'outputPcap' 'filterImplementation' 'filterImplementationFullClassName'"`, where:
1. `'inputPcap'` is the path to the original `.pcap` file for which a filtered `.pcap` is desired.
2. `'outputPcap'`is the path to the file that is to store the filtered network trace.
3. `'filterImplementation'` is a Java class that implements `java.util.function.Function<org.pcap4j.core.PcapPacket, java.lang.Boolean>`. This is where you specify your logic that decides if a packet is to be included in the filtered network trace. You may specify either a `.java` or a `.class` file. If a `.java` file is specified, the tool will compile the source file and output the corresponding `.class` file in the source file's directory.
4. `'filterImplementationFullClassName'` is the fully qualified name of `filterImplementation`.
