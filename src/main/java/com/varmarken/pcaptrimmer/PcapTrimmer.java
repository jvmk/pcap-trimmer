package com.varmarken.pcaptrimmer;

import org.pcap4j.core.*;
import org.pcap4j.packet.namednumber.DataLinkType;

import javax.tools.JavaCompiler;
import javax.tools.ToolProvider;
import java.io.File;
import java.io.FileNotFoundException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.function.Function;

/**
 * Given an input pcap file {@code inFile}, and output pcap file {@code outFile}, and a packet filter {@code filter},
 * writes those packets in {@code inFile} that passes through {@code filter} to {@code outFile}.
 */
public class PcapTrimmer implements PacketListener {

    private static final String ARG0_NAME = "inputPcap";
    private static final String ARG1_NAME = "outputPcap";
    private static final String ARG2_NAME = "filterImplementation";
    private static final String ARG3_NAME = "filterImplementationFullClassName";

    private static final String USAGE_HINT = String.format("Usage: java %s %s %s %s %s", PcapTrimmer.class.getName(),
            ARG0_NAME, ARG1_NAME, ARG2_NAME, ARG3_NAME);

    private static final String SRC_FILE_EXTENSION = ".java";
    private static final String CLASS_FILE_EXTENSION = ".class";


    public static void main(String[] args) throws FileNotFoundException, NotOpenException, PcapNativeException {
        if (args.length < 4) {
            System.out.println(USAGE_HINT);
            return;
        }
        String inputPcap = args[0];
        String outputPcap = args[1];
        String filterImpl = args[2];
        String filterImplFullClassName = args[3];
        // User-defined filter (Function<PcapPacket, Boolean> implementation) should be a java source or class file.
        if (!isSourceFile(filterImpl) && !isClassFile(filterImpl)) {
            System.out.printf("Invalid value for '%s' arg. Expected a '.java' or '.class' file.%s",
                    ARG2_NAME, System.lineSeparator());
            System.out.println(USAGE_HINT);
            return;
        }
        if (isSourceFile(filterImpl)) {
            // User specified a source file, so compile it.
            JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
            int compilationResult = compiler.run(null, null, null, filterImpl);
            if (compilationResult != 0) {
                System.err.printf("Compilation of '%s' failed with error code %d", filterImpl, compilationResult);
                System.err.println();
                return;
            }
            // Update the filter implementation filename to point to the newly created .class file.
            // This class file should reside in the same directory as the source file.
            filterImpl = filterImpl.substring(0, filterImpl.lastIndexOf(SRC_FILE_EXTENSION)) + CLASS_FILE_EXTENSION;

        }
        Function<PcapPacket, Boolean> filter;
        try {
            // Load the (potentially freshly) compiled filter implementation
            URLClassLoader classLoader = URLClassLoader.newInstance(
                    new URL[]{new File(filterImpl).getParentFile().toURI().toURL()});
            Class<?> filterImplClass = Class.forName(filterImplFullClassName, true, classLoader);
            Object untypedInstance = filterImplClass.getDeclaredConstructor().newInstance();
            filter = (Function<PcapPacket, Boolean>) untypedInstance;
        } catch (ReflectiveOperationException roe) {
            System.err.println("Could not instantiate provided filter implementation. Exception details follow.");
            System.err.println(roe.getMessage());
            roe.printStackTrace();
            return;
        } catch (MalformedURLException mue) {
            System.err.printf("Could not convert arg '%s' to URL when attempting to load filter implementation.",
                    ARG2_NAME);
            System.err.println();
            System.err.println(mue.getMessage());
            mue.printStackTrace();
            return;
        } catch (ClassCastException cce) {
            System.err.printf("Provided filter implementation does not conform to interface %s<%s, %s>.",
                    Function.class.getName(), PcapPacket.class.getName(), Boolean.class.getName());
            return;
        }
        // Trim the pcap using the provided filter.
        PcapTrimmer pcapTrimmer = new PcapTrimmer(inputPcap, outputPcap, filter);
        pcapTrimmer.trimPcap();
    }

    private static boolean isSourceFile(String filename) {
        return filename.endsWith(SRC_FILE_EXTENSION);
    }

    private static boolean isClassFile(String filename) {
        return filename.endsWith(CLASS_FILE_EXTENSION);
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
