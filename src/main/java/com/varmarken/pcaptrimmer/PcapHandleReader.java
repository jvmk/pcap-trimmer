package com.varmarken.pcaptrimmer;


import org.pcap4j.core.*;

import java.io.EOFException;
import java.util.Objects;
import java.util.concurrent.TimeoutException;

/**
 * Reads packets from a {@link PcapHandle} (online or offline) and delivers packets read to a group of
 * {@link PacketListener}s.
 *
 * @author Janus Varmarken
 */
class PcapHandleReader {

    private final PcapHandle mHandle;
    private final PacketListener[] mPacketListeners;
    private volatile boolean mTerminated = false;

    /**
     * Create a {@code PcapHandleReader}.
     *
     * @param handle An <em>open</em> {@link PcapHandle} that packets will be read from.
     * @param packetListeners One or more {@link PacketListener}s that will receive packets read from {@code handle}.
     */
    PcapHandleReader(PcapHandle handle, PacketListener... packetListeners) {
        mHandle = Objects.requireNonNull(handle, "Handle cannot be null");
        if (packetListeners == null || packetListeners.length == 0) {
            throw new IllegalArgumentException(
                    String.format("No %s(s) provided. Does not make sense to read packets only to ignore them.",
                            PacketListener.class.getSimpleName())
            );
        }
        mPacketListeners = packetListeners;
    }


    /**
     * Start reading packets from the {@code PcapHandle} that was provided when this instance was created.
     * Note that this method will close the {@code PcapHandle} before returning, so the client should <em>not</em>
     * attempt to read from the {@code PcapHandle} in statements subsequent to its invocation of this method.
     *
     * @throws NotOpenException if the {@link PcapHandle} provided when this instance was created is (no longer) open.
     * @throws PcapNativeException if an error occurs in the pcap native library.
     */
    void readFromHandle() throws PcapNativeException, NotOpenException {
        while (!mTerminated) {
            try {
                PcapPacket packet = mHandle.getNextPacketEx();
                for (PacketListener listener : mPacketListeners) {
                    listener.gotPacket(packet);
                }
            } catch (TimeoutException te) {
                // This can occur "if packets are being read from a live capture and the timeout expired".
                // Note that this does not necessarily mean that we want to terminate the reader: it might just be
                // that the interface is experiencing a silent period (no traffic going in/out).
                // No need to check termination flag here. Can defer it to the loop condition as it is the next
                // instruction anyway.
                System.err.println("timeout occurred while reading live from a network interface");
                te.printStackTrace();
                continue;
            } catch (EOFException eofe) {
                // Reached end of file, so we're done.
                mTerminated = true;
            }
        }
        mHandle.close();
    }

    /**
     * Stop reading from the wrapped {@link PcapHandle}. Note that this call only <em>initiates</em> the shutdown by
     * setting a termination flag. Shutdown will be deferred until the time at which this flag can be checked by
     * {@link #readFromHandle()}. For example, if {@link #readFromHandle()} is currently in the middle of a blocking
     * call to {@link PcapHandle#getNextPacketEx()}, shutdown will not occur until the next packet is returned from the
     * wrapped {@link PcapHandle} or its read timeout expires. Use {@link #hasTerminated()} to check if the shutdown
     * has completed.
     */
    void stopReading() {
        mTerminated = true;
    }

    /**
     * Checks if this {@link PcapHandleReader} has gracefully terminated, i.e., that the wrapped {@link PcapHandle} has
     * been closed.
     *
     * @return {@code true} if this {@link PcapHandleReader} has terminated, {@code false} otherwise.
     */
    boolean hasTerminated() {
        return mTerminated && !mHandle.isOpen();
    }

}
