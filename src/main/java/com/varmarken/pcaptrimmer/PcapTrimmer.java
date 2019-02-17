package com.varmarken.pcaptrimmer;

import org.pcap4j.core.*;
import org.pcap4j.packet.DnsPacket;
import org.pcap4j.packet.namednumber.DataLinkType;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.function.Function;

/**
 * Given an input pcap file {@code inFile}, and output pcap file {@code outFile}, and a packet filter {@code filter},
 * writes those packets in {@code inFile} that passes through {@code filter} to {@code outFile}.
 */
public class PcapTrimmer implements PacketListener {

    public static void main(String[] args) throws FileNotFoundException, NotOpenException, PcapNativeException {
        // TODO let client specify packet filter.
        if (args.length < 2) {
            System.out.printf("Usage: java %s inputPcap outputPcap%s", PcapTrimmer.class.getName(), System.lineSeparator());
            return;
        }
        String inFile = args[0];
        String outFile = args[1];

        // Simple example that makes the output pcap file only contain DNS traffic.
        PcapTrimmer pcapTrimmer = new PcapTrimmer(inFile, outFile, (pkt) -> {
            DnsPacket dnsPacket = pkt.get(DnsPacket.class);
            return dnsPacket != null;
        });
        pcapTrimmer.trimPcap();
    }

    /**
     * By default, we assume that the trace is an Ethernet-trace, but allow client code the ability to change that
     * assumption.
     */
    private volatile DataLinkType mDataLinkType = DataLinkType.EN10MB;

    /**
     * Max packet size for packets in input trace. As the default value is much greater than the standard Ethernet MTU,
     * most clients will not need to change this parameter.
     */
    private volatile int mSnapshotLength = 65536;

    /**
     * The filter that determines if a packet in the input trace should be included in the output trace.
     */
    private final Function<PcapPacket, Boolean> mFilter;

    /**
     * The input pcap file.
     */
    private final File mOrigPcap;

    /**
     * The output pcap file.
     */
    private final File mTrimmedPcap;

    /**
     * Outputs packets to {@link #mTrimmedPcap}.
     */
    private volatile PcapDumper mPcapWriter;

    /**
     * Create a new {@code PcapTrimmer}.
     * @param originalPcap Identifies the original (i.e., the input) pcap file.
     * @param trimmedPcap Identifies the output pcap file.
     * @param filter A function that determines if a given packet should be included in the output pcap file or not.
     *               The function should return {@code true}, if a packet is to be included in the output pcap file,
     *               and {@code false} if the packet should be ignored.
     */
    public PcapTrimmer(File originalPcap, File trimmedPcap, Function<PcapPacket, Boolean> filter) {
        mOrigPcap = originalPcap;
        mTrimmedPcap = trimmedPcap;
        mFilter = filter;
    }

    /**
     * Create a new {@code PcapTrimmer}.
     * @param originalPcapAbsPath Identifies the original (i.e., the input) pcap file.
     * @param trimmedPcapAbsPath Identifies the output pcap file.
     * @param filter A function that determines if a given packet should be included in the output pcap file or not.
     *               The function should return {@code true}, if a packet is to be included in the output pcap file,
     *               and {@code false} if the packet should be ignored.
     */
    public PcapTrimmer(String originalPcapAbsPath, String trimmedPcapAbsPath, Function<PcapPacket, Boolean> filter) {
        this(new File(originalPcapAbsPath), new File(trimmedPcapAbsPath), filter);
    }

    /**
     * Read the input (original) pcap file, and output those packets that pass through the filter to the output pcap file.
     * @throws FileNotFoundException if the input pcap file was not found.
     * @throws PcapNativeException if an error occurs in the pcap native library.
     * @throws NotOpenException if the output pcap file cannot be written.
     */
    public void trimPcap() throws FileNotFoundException, PcapNativeException, NotOpenException {
        mPcapWriter = Pcaps.openDead(mDataLinkType, mSnapshotLength).dumpOpen(mTrimmedPcap.getAbsolutePath());
        PcapFileReader fileReader = new PcapFileReader(mOrigPcap);
        fileReader.readFile(this);
        mPcapWriter.flush();
        mPcapWriter.close();
    }

    /**
     * Invoked whenever a packet is read from the input pcap file.
     * @param packet The packet read from the input pcap file.
     */
    @Override
    public void gotPacket(PcapPacket packet) {
        // Write packet to output pcap file if it passes through the filter.
        if (mFilter.apply(packet)) {
            try {
                mPcapWriter.dump(packet);
            } catch (NotOpenException noe) {
                // As we're not exposing the PcapDumper to external code, we should remain in complete control of when
                // it is closed and as a result this should never happen.
                throw new AssertionError(noe);
            }
        }
    }

    /**
     * Set the data link type for the input trace (pcap file). By default, the trace is assumed to be an Ethernet-trace.
     */
    public void setDataLinkType(DataLinkType dlt) {
        mDataLinkType = dlt;
    }

    /**
     * Specify the max packet size for packets in the input trace. As the default value is much greater than the
     * standard Ethernet MTU, most clients will not need to change this parameter.
     */
    public void setSnapshotLength(int snapshotLength) {
        mSnapshotLength = snapshotLength;
    }

}
