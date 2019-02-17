package com.varmarken.pcaptrimmer;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;

/**
 * A simple {@link ClassLoader} that loads classes from a given directory and does not attempt to drill down into sub
 * directories when the class to be loaded is part of a package (i.e., when it is not in the default package). For
 * example, if the class to be loaded is {@code com.example.MyClass}, and it is specified to reside in
 * {@code /some/path/}, this class loader will attempt to load the class directly from {@code /some/path}, whereas
 * a {@link java.net.URLClassLoader} would attempt to load the class from {@code /some/path/com/example/}.
 *
 * @author Janus Varmarken
 */
class SingleDirectoryClassLoader extends ClassLoader {


    private static final String CLASS_FILE_EXTENSION = ".class";

    /**
     * Directory that contains the class to be loaded.
     */
    private final File mDir;

    /**
     * Create a {@code SingleDirectoryClassLoader} that loads classes from the directory specified by
     * {@code containingDirectory}.
     *
     * @param containingDirectory Directory that contains the class to be loaded.
     */
    SingleDirectoryClassLoader(String containingDirectory) throws FileNotFoundException {
        this(new File(containingDirectory));
    }

    /**
     * Create a {@code SingleDirectoryClassLoader} that loads classes from the directory specified by
     * {@code containingDirectory}.
     *
     * @param containingDirectory Directory that contains the class to be loaded.
     */
    SingleDirectoryClassLoader(File containingDirectory) throws FileNotFoundException {
        mDir = containingDirectory;
        if (!mDir.isDirectory()) {
            throw new FileNotFoundException("not a directory");
        }
    }

    @Override
    protected Class<?> findClass(String fullyQualifiedClassName) throws ClassNotFoundException {
        try {
            byte[] classData = loadClassData(fullyQualifiedClassName);
            return defineClass(fullyQualifiedClassName, classData, 0, classData.length);
        } catch (IOException ioe) {
            throw new ClassNotFoundException("Could not read class from file.", ioe);
        }
    }

    private byte[] loadClassData(String fullyQualifiedClassName) throws IOException {
        // Drop the package prefix, if any, as we want to load the class from current directory
        int lastDot = fullyQualifiedClassName.lastIndexOf(".");
        String simpleClassName = lastDot > -1 ? fullyQualifiedClassName.substring(lastDot+1) : fullyQualifiedClassName;
        File classFile = new File(mDir, simpleClassName + CLASS_FILE_EXTENSION);
        return Files.readAllBytes(classFile.toPath());
    }
}
