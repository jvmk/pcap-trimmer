package com.varmarken.pcaptrimmer;

import org.pcap4j.core.*;

import java.io.File;
import java.io.FileNotFoundException;

/**
 * Simple wrapper for the boilerplate code necessary for opening and reading a pcap file in pcap4j.
 */
class PcapFileReader {

    /**
     * The pcap file to be read.
     */
    private final File mPcapFile;

    /**
     * Create a {@code PcapFileReader} that reads the pcap file specified using {@code pcapFile}.
     * @param pcapFile The pcap file that is to be read.
     * @throws FileNotFoundException if {@code pcapFile} does not exist.
     */
    PcapFileReader(File pcapFile) throws FileNotFoundException {
        mPcapFile = pcapFile;
        if (!mPcapFile.exists()) {
            throw new FileNotFoundException("input pcap file not found");
        }
    }

    /**
     * Reads the pcap file specified when creating this instance. Every packet read from the pcap file is delivered to
     * each and every {@link PacketListener} in {@code packetListeners}.
     * @param packetListeners One or more {@link PacketListener}s that wishes to process the packets read from the pcap
     *                        file.
     * @throws PcapNativeException if an error occurs in the pcap native library.
     */
    void readFile(PacketListener... packetListeners) throws PcapNativeException {
        // Idiom for opening a pcap file in pcap4j
        PcapHandle pcapHandle;
        try {
            pcapHandle = Pcaps.openOffline(mPcapFile.getAbsolutePath(), PcapHandle.TimestampPrecision.NANO);
        } catch (PcapNativeException pne) {
            pcapHandle = Pcaps.openOffline(mPcapFile.getAbsolutePath());
        }
        // Delegate read logic to PcapHandleReader
        PcapHandleReader reader = new PcapHandleReader(pcapHandle, packetListeners);
        try {
            reader.readFromHandle();
        } catch (NotOpenException noe) {
            // This should never happen as we do not expose the pcap handle to other code (except PcapHandleReader),
            // so we're in full control of when the handle is closed.
            throw new AssertionError(noe);
        }
    }

}
