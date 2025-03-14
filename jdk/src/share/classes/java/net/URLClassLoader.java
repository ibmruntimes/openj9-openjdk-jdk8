/*
 * Copyright (c) 1997, 2018, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

/*
 * ===========================================================================
 * (c) Copyright IBM Corp. 2000, 2025 All Rights Reserved
 * ===========================================================================
 */

package java.net;

import java.io.Closeable;
import java.io.File;
import java.io.FilePermission;
import java.io.IOException;
import java.io.InputStream;
import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.CodeSigner;
import java.security.CodeSource;
import java.security.Permission;
import java.security.PermissionCollection;
import java.security.PrivilegedAction;
import java.security.PrivilegedExceptionAction;
import java.security.SecureClassLoader;
import java.util.Enumeration;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.Set;
import java.util.Vector;
import java.util.WeakHashMap;
import java.util.jar.Attributes;
import java.util.jar.Attributes.Name;
import java.util.jar.JarFile;
import java.util.jar.Manifest;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.util.regex.PatternSyntaxException;
import java.util.StringTokenizer;
import sun.misc.Resource;
import sun.misc.SharedSecrets;
import sun.misc.URLClassPath;
import sun.net.www.ParseUtil;
import sun.security.util.SecurityConstants;
import com.ibm.oti.shared.Shared;
import com.ibm.oti.shared.SharedClassHelperFactory;
import com.ibm.oti.shared.SharedClassURLClasspathHelper;
import com.ibm.oti.shared.HelperAlreadyDefinedException;

/**
 * This class loader is used to load classes and resources from a search
 * path of URLs referring to both JAR files and directories. Any URL that
 * ends with a '/' is assumed to refer to a directory. Otherwise, the URL
 * is assumed to refer to a JAR file which will be opened as needed.
 * <p>
 * The AccessControlContext of the thread that created the instance of
 * URLClassLoader will be used when subsequently loading classes and
 * resources.
 * <p>
 * The classes that are loaded are by default granted permission only to
 * access the URLs specified when the URLClassLoader was created.
 *
 * @author  David Connelly
 * @since   1.2
 */
public class URLClassLoader extends SecureClassLoader implements Closeable {
    /* The search path for classes and resources */
    private final URLClassPath ucp;

    /* The context to be used when loading classes and resources */
    private final AccessControlContext acc;

    /* Private member fields used for Shared classes*/
    private SharedClassURLClasspathHelper sharedClassURLClasspathHelper;
    private SharedClassMetaDataCache sharedClassMetaDataCache;

    /*
     * Wrapper class for maintaining the index of where the metadata (codesource and manifest)
     * is found - used only in Shared classes context.
     */
    private class SharedClassIndexHolder implements SharedClassURLClasspathHelper.IndexHolder {
        int index;

        public void setIndex(int index) {
            this.index = index;
        }
    }

    /*
     * Wrapper class for internal storage of metadata (codesource and manifest) associated with
     * shared class - used only in Shared classes context.
     */
    private class SharedClassMetaData {
        private CodeSource codeSource;
        private Manifest manifest;

        SharedClassMetaData(CodeSource codeSource, Manifest manifest) {
            this.codeSource = codeSource;
            this.manifest = manifest;
        }
        public CodeSource getCodeSource() { return codeSource; }
        public Manifest getManifest() { return manifest; }
    }

    /*
     * Represents a collection of SharedClassMetaData objects retrievable by
     * index.
     */
    private class SharedClassMetaDataCache {
        private final static int BLOCKSIZE = 10;
        private SharedClassMetaData[] store;

        public SharedClassMetaDataCache(int initialSize) {
            /* Allocate space for an initial amount of metadata entries */
            store = new SharedClassMetaData[initialSize];
        }

        /**
         * Retrieves the SharedClassMetaData stored at the given index, or null
         * if no SharedClassMetaData was previously stored at the given index
         * or the index is out of range.
         */
        public synchronized SharedClassMetaData getSharedClassMetaData(int index) {
            if (index < 0 || store.length < (index+1)) {
                return null;
            }
            return store[index];
        }

        /**
         * Stores the supplied SharedClassMetaData at the given index in the
         * store. The store will be grown to contain the index if necessary.
         */
        public synchronized void setSharedClassMetaData(int index,
                                                     SharedClassMetaData data) {
            ensureSize(index);
            store[index] = data;
        }

        /* Ensure that the store can hold at least index number of entries */
        private synchronized void ensureSize(int index) {
            if (store.length < (index+1)) {
                int newSize = (index+BLOCKSIZE);
                SharedClassMetaData[] newSCMDS = new SharedClassMetaData[newSize];
                System.arraycopy(store, 0, newSCMDS, 0, store.length);
                store = newSCMDS;
            }
        }
    }

    /*
     * Return true if shared classes support is active, otherwise false.
     */
    private boolean usingSharedClasses() {
        return (sharedClassURLClasspathHelper != null);
    }

    /*
     * Initialize support for shared classes.
     */
    private void initializeSharedClassesSupport(URL[] initialClassPath) {
        /* get the Shared class helper and initialize the metadata store if we are sharing */
        SharedClassHelperFactory sharedClassHelperFactory = Shared.getSharedClassHelperFactory();

        if (sharedClassHelperFactory != null) {
            try {
                this.sharedClassURLClasspathHelper = sharedClassHelperFactory.getURLClasspathHelper(this, initialClassPath);
            } catch (HelperAlreadyDefinedException ex) { // thrown if we get 2 types of helper for the same classloader
                ex.printStackTrace();
            }
            /* Only need to create a meta data cache if using shared classes */
            if (usingSharedClasses()) {
                /* Create a metadata cache */
                this.sharedClassMetaDataCache = new SharedClassMetaDataCache(initialClassPath.length);
            }
        }
    }

    /**
     * Constructs a new URLClassLoader for the given URLs. The URLs will be
     * searched in the order specified for classes and resources after first
     * searching in the specified parent class loader. Any URL that ends with
     * a '/' is assumed to refer to a directory. Otherwise, the URL is assumed
     * to refer to a JAR file which will be downloaded and opened as needed.
     *
     * <p>If there is a security manager, this method first
     * calls the security manager's {@code checkCreateClassLoader} method
     * to ensure creation of a class loader is allowed.
     *
     * @param urls the URLs from which to load classes and resources
     * @param parent the parent class loader for delegation
     * @exception  SecurityException  if a security manager exists and its
     *             {@code checkCreateClassLoader} method doesn't allow
     *             creation of a class loader.
     * @exception  NullPointerException if {@code urls} is {@code null}.
     * @see SecurityManager#checkCreateClassLoader
     */
    public URLClassLoader(URL[] urls, ClassLoader parent) {
        super(parent);
        // this is to make the stack depth consistent with 1.1
        SecurityManager security = System.getSecurityManager();
        if (security != null) {
            security.checkCreateClassLoader();
        }
        initializeSharedClassesSupport(urls);
        this.acc = AccessController.getContext();
        ucp = new URLClassPath(urls, null, this.acc, sharedClassURLClasspathHelper);
    }

    URLClassLoader(URL[] urls, ClassLoader parent,
                   AccessControlContext acc) {
        super(parent);
        // this is to make the stack depth consistent with 1.1
        SecurityManager security = System.getSecurityManager();
        if (security != null) {
            security.checkCreateClassLoader();
        }
        this.acc = acc;
        ucp = new URLClassPath(urls, acc);
    }

    /**
     * Constructs a new URLClassLoader for the specified URLs using the
     * default delegation parent {@code ClassLoader}. The URLs will
     * be searched in the order specified for classes and resources after
     * first searching in the parent class loader. Any URL that ends with
     * a '/' is assumed to refer to a directory. Otherwise, the URL is
     * assumed to refer to a JAR file which will be downloaded and opened
     * as needed.
     *
     * <p>If there is a security manager, this method first
     * calls the security manager's {@code checkCreateClassLoader} method
     * to ensure creation of a class loader is allowed.
     *
     * @param urls the URLs from which to load classes and resources
     *
     * @exception  SecurityException  if a security manager exists and its
     *             {@code checkCreateClassLoader} method doesn't allow
     *             creation of a class loader.
     * @exception  NullPointerException if {@code urls} is {@code null}.
     * @see SecurityManager#checkCreateClassLoader
     */
    public URLClassLoader(URL[] urls) {
        super();
        // this is to make the stack depth consistent with 1.1
        SecurityManager security = System.getSecurityManager();
        if (security != null) {
            security.checkCreateClassLoader();
        }
        initializeSharedClassesSupport(urls);
        this.acc = AccessController.getContext();
        ucp = new URLClassPath(urls, null, this.acc, sharedClassURLClasspathHelper);
    }

    URLClassLoader(URL[] urls, AccessControlContext acc) {
        super();
        // this is to make the stack depth consistent with 1.1
        SecurityManager security = System.getSecurityManager();
        if (security != null) {
            security.checkCreateClassLoader();
        }
        this.acc = acc;
        ucp = new URLClassPath(urls, acc);
    }

    /**
     * Constructs a new URLClassLoader for the specified URLs, parent
     * class loader, and URLStreamHandlerFactory. The parent argument
     * will be used as the parent class loader for delegation. The
     * factory argument will be used as the stream handler factory to
     * obtain protocol handlers when creating new jar URLs.
     *
     * <p>If there is a security manager, this method first
     * calls the security manager's {@code checkCreateClassLoader} method
     * to ensure creation of a class loader is allowed.
     *
     * @param urls the URLs from which to load classes and resources
     * @param parent the parent class loader for delegation
     * @param factory the URLStreamHandlerFactory to use when creating URLs
     *
     * @exception  SecurityException  if a security manager exists and its
     *             {@code checkCreateClassLoader} method doesn't allow
     *             creation of a class loader.
     * @exception  NullPointerException if {@code urls} is {@code null}.
     * @see SecurityManager#checkCreateClassLoader
     */
    public URLClassLoader(URL[] urls, ClassLoader parent,
                          URLStreamHandlerFactory factory) {
        super(parent);
        // this is to make the stack depth consistent with 1.1
        SecurityManager security = System.getSecurityManager();
        if (security != null) {
            security.checkCreateClassLoader();
        }
        initializeSharedClassesSupport(urls);
        acc = AccessController.getContext();
        ucp = new URLClassPath(urls, factory, acc, sharedClassURLClasspathHelper);
    }

    /* A map (used as a set) to keep track of closeable local resources
     * (either JarFiles or FileInputStreams). We don't care about
     * Http resources since they don't need to be closed.
     *
     * If the resource is coming from a jar file
     * we keep a (weak) reference to the JarFile object which can
     * be closed if URLClassLoader.close() called. Due to jar file
     * caching there will typically be only one JarFile object
     * per underlying jar file.
     *
     * For file resources, which is probably a less common situation
     * we have to keep a weak reference to each stream.
     */

    private WeakHashMap<Closeable,Void>
        closeables = new WeakHashMap<>();

    /**
     * Returns an input stream for reading the specified resource.
     * If this loader is closed, then any resources opened by this method
     * will be closed.
     *
     * <p> The search order is described in the documentation for {@link
     * #getResource(String)}.  </p>
     *
     * @param  name
     *         The resource name
     *
     * @return  An input stream for reading the resource, or {@code null}
     *          if the resource could not be found
     *
     * @since  1.7
     */
    public InputStream getResourceAsStream(String name) {
        URL url = getResource(name);
        try {
            if (url == null) {
                return null;
            }
            URLConnection urlc = url.openConnection();
            InputStream is = urlc.getInputStream();
            if (urlc instanceof JarURLConnection) {
                JarURLConnection juc = (JarURLConnection)urlc;
                JarFile jar = juc.getJarFile();
                synchronized (closeables) {
                    if (!closeables.containsKey(jar)) {
                        closeables.put(jar, null);
                    }
                }
            } else if (urlc instanceof sun.net.www.protocol.file.FileURLConnection) {
                synchronized (closeables) {
                    closeables.put(is, null);
                }
            }
            return is;
        } catch (IOException e) {
            return null;
        }
    }

   /**
    * Closes this URLClassLoader, so that it can no longer be used to load
    * new classes or resources that are defined by this loader.
    * Classes and resources defined by any of this loader's parents in the
    * delegation hierarchy are still accessible. Also, any classes or resources
    * that are already loaded, are still accessible.
    * <p>
    * In the case of jar: and file: URLs, it also closes any files
    * that were opened by it. If another thread is loading a
    * class when the {@code close} method is invoked, then the result of
    * that load is undefined.
    * <p>
    * The method makes a best effort attempt to close all opened files,
    * by catching {@link IOException}s internally. Unchecked exceptions
    * and errors are not caught. Calling close on an already closed
    * loader has no effect.
    * <p>
    * @exception IOException if closing any file opened by this class loader
    * resulted in an IOException. Any such exceptions are caught internally.
    * If only one is caught, then it is re-thrown. If more than one exception
    * is caught, then the second and following exceptions are added
    * as suppressed exceptions of the first one caught, which is then re-thrown.
    *
    * @exception SecurityException if a security manager is set, and it denies
    *   {@link RuntimePermission}{@code ("closeClassLoader")}
    *
    * @since 1.7
    */
    public void close() throws IOException {
        SecurityManager security = System.getSecurityManager();
        if (security != null) {
            security.checkPermission(new RuntimePermission("closeClassLoader"));
        }
        List<IOException> errors = ucp.closeLoaders();

        // now close any remaining streams.

        synchronized (closeables) {
            Set<Closeable> keys = closeables.keySet();
            for (Closeable c : keys) {
                try {
                    c.close();
                } catch (IOException ioex) {
                    errors.add(ioex);
                }
            }
            closeables.clear();
        }

        if (errors.isEmpty()) {
            return;
        }

        IOException firstex = errors.remove(0);

        // Suppress any remaining exceptions

        for (IOException error: errors) {
            firstex.addSuppressed(error);
        }
        throw firstex;
    }

    /**
     * Appends the specified URL to the list of URLs to search for
     * classes and resources.
     * <p>
     * If the URL specified is {@code null} or is already in the
     * list of URLs, or if this loader is closed, then invoking this
     * method has no effect.
     *
     * @param url the URL to be added to the search path of URLs
     */
    protected void addURL(URL url) {
        ucp.addURL(url);
    }

    /**
     * Returns the search path of URLs for loading classes and resources.
     * This includes the original list of URLs specified to the constructor,
     * along with any URLs subsequently appended by the addURL() method.
     * @return the search path of URLs for loading classes and resources.
     */
    public URL[] getURLs() {
        return ucp.getURLs();
    }

    /* Stores a list of classes for which is show detailed class loading */
    private static Vector showClassLoadingFor = null;
    /* Caches whether the vector showClassLoadingFor is empty */
    private static boolean showLoadingMessages = false;
    /* Property to use to setup the detailed classloading output */
    private final static String showClassLoadingProperty = "ibm.cl.verbose";

    /*
     * Initializes the showClassLoadingFor vector. All expressions are precompiled
     */
    static
    {
        Vector showClassLoadingFor = new Vector();
        String classes = System.getProperty(showClassLoadingProperty);
        /* If the property exists then process the supplied file expressions */
        if (classes != null) {
            StringTokenizer classMatchers = new StringTokenizer(classes, ",");
            while (classMatchers.hasMoreTokens()) {
                String classMatcher = classMatchers.nextToken();
                /* Do the replacements to allow more readable expressions to be supplied */
                String classMatcherExp = classMatcher.replaceAll("\\.", "\\.");
                classMatcherExp = classMatcherExp.replaceAll("\\*", ".*");
                Pattern pattern;
                /* Add the compiled pattern to the vector */
                try {
                    pattern = Pattern.compile(classMatcherExp);
                    showClassLoadingFor.addElement(pattern);
                } catch (PatternSyntaxException e) {
                    /*
                     * The user has supplied something which has is not
                     * a legal regular expression (or isn't now that it has been
                     * transformed!) Warn the user and ignore this expression
                     */
                    System.err.println("Illegal class matching expression \"" + classMatcher +
                        "\" supplied by property " + showClassLoadingProperty);
                }
            }
        }
        /*
         * Cache whether a check should be made to see whether to show loading messages for
         * a particular class
         */
        if (!showClassLoadingFor.isEmpty()) {
            showLoadingMessages = true;
        }
        URLClassLoader.showClassLoadingFor = showClassLoadingFor;
    }

    /*
     * Returns whether the class loading should be explicitly shown for a
     * particular class. This is determined by the system property ibm.cl.verbose
     * which contains a comma separated list of file expressions.
     * A file expression being a regular expression but with .* substituted for *
     * and \. substituted for . to allow a more readable form to be used
     * If no property exists or contains no expressions then showClassLoadingFor
     * will be an empty vector and this will be the only test each time this function
     * is called. Otherwise name will be matched against each expression in the vector
     * and if a match is found true is returned, otherwise false
     */
    private boolean showClassLoading(String name)
    {
        /* If there are supplied expressions try and match this class name against them */
        if (URLClassLoader.showLoadingMessages) {
            Enumeration patterns = URLClassLoader.showClassLoadingFor.elements();
            while (patterns.hasMoreElements()) {
                Pattern pattern = (Pattern)patterns.nextElement();
                Matcher matcher = pattern.matcher(name);
                if (matcher.matches()) {
                    return true;
                }
            }
        }
        /* Either no expressions or no matches */
        return false;
    }

    /**
     * Finds and loads the class with the specified name from the URL search
     * path. Any URLs referring to JAR files are loaded and opened as needed
     * until the class is found.
     *
     * @param name the name of the class
     * @return the resulting class
     * @exception ClassNotFoundException if the class could not be found,
     *            or if the loader is closed.
     * @exception NullPointerException if {@code name} is {@code null}.
     */
    protected Class<?> findClass(final String name)
        throws ClassNotFoundException
    {
        final Class<?> result;
        try {
            /* Try to find the class from the shared cache using the class name.  If we found the class
             * and if we have its corresponding metadata (codesource and manifest entry) already cached,
             * then we define the class passing in these parameters.  If however, we do not have the
             * metadata cached, then we define the class as normal.  Also, if we do not find the class
             * from the shared class cache, we define the class as normal.
             */
            if (usingSharedClasses()) {
                SharedClassIndexHolder sharedClassIndexHolder = new SharedClassIndexHolder();
                byte[] sharedClazz = sharedClassURLClasspathHelper.findSharedClass(name, sharedClassIndexHolder);

                if (sharedClazz != null) {
                    int indexFoundData = sharedClassIndexHolder.index;
                    SharedClassMetaData metadata = sharedClassMetaDataCache.getSharedClassMetaData(indexFoundData);
                    if (metadata != null) {
                        try {
                            Class clazz = defineClass(name,sharedClazz,
                                               metadata.getCodeSource(),
                                               metadata.getManifest());
                            return clazz;
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                   }
               }
            }
            ClassFinder loader = new ClassFinder(name, this);
            Class clazz = (Class)AccessController.doPrivileged(loader, acc);
            if (clazz == null) {
                       throw new ClassNotFoundException(name);
            }
            return clazz;

        } catch (java.security.PrivilegedActionException pae) {
            throw (ClassNotFoundException) pae.getException();
        }
    }

    /*
     * Retrieve the package using the specified package name.
     * If non-null, verify the package using the specified code
     * source and manifest.
     */
    private Package getAndVerifyPackage(String pkgname,
                                        Manifest man, URL url) {
        Package pkg = getPackage(pkgname);
        if (pkg != null) {
            // Package found, so check package sealing.
            if (pkg.isSealed()) {
                // Verify that code source URL is the same.
                if (!pkg.isSealed(url)) {
                    throw new SecurityException(
                        "sealing violation: package " + pkgname + " is sealed");
                }
            } else {
                // Make sure we are not attempting to seal the package
                // at this code source URL.
                if ((man != null) && isSealed(pkgname, man)) {
                    throw new SecurityException(
                        "sealing violation: can't seal package " + pkgname +
                        ": already loaded");
                }
            }
        }
        return pkg;
    }

    // Also called by VM to define Package for classes loaded from the CDS
    // archive
    private void definePackageInternal(String pkgname, Manifest man, URL url)
    {
        if (getAndVerifyPackage(pkgname, man, url) == null) {
            try {
                if (man != null) {
                    definePackage(pkgname, man, url);
                } else {
                    definePackage(pkgname, null, null, null, null, null, null, null);
                }
            } catch (IllegalArgumentException iae) {
                // parallel-capable class loaders: re-verify in case of a
                // race condition
                if (getAndVerifyPackage(pkgname, man, url) == null) {
                    // Should never happen
                    throw new AssertionError("Cannot find package " +
                                             pkgname);
                }
            }
        }
    }

    /*
     * Defines a Class using the class bytes obtained from the specified
     * Resource. The resulting Class must be resolved before it can be
     * used.
     */
    private Class<?> defineClass(String name, Resource res) throws IOException {
        Class clazz = null;
        CodeSource cs = null;
        Manifest man = null;
        long t0 = System.nanoTime();
        int i = name.lastIndexOf('.');
        URL url = res.getCodeSourceURL();
        if (i != -1) {
            String pkgname = name.substring(0, i);
            // Check if package already loaded.
            man = res.getManifest();
            definePackageInternal(pkgname, man, url);
        }
        // Now read the class bytes and define the class
        java.nio.ByteBuffer bb = res.getByteBuffer();
        if (bb != null) {
            // Use (direct) ByteBuffer:
            CodeSigner[] signers = res.getCodeSigners();
            cs = new CodeSource(url, signers);
            clazz = defineClass(name, bb, cs);
        } else {
             byte[] b = res.getBytes();
             // must read certificates AFTER reading bytes.
             CodeSigner[] signers = res.getCodeSigners();
             cs = new CodeSource(url, signers);
             clazz = defineClass(name, b, 0, b.length, cs);
        }

        /*
         * Since we have already stored the class path index (of where this resource came from), we can retrieve
         * it here.  The storing is done in getResource() in URLClassPath.java.  The index is the specified
         * position in the URL search path (see getLoader()).  The storeSharedClass() call below, stores the
         * class in the shared class cache for future use.
         */
        if (usingSharedClasses()) {

            /* Determine the index into the search path for this class */
            int index = res.getClasspathLoadIndex();
            /* Check to see if we have already cached metadata for this index */
            SharedClassMetaData metadata = sharedClassMetaDataCache.getSharedClassMetaData(index);
            /* If we have not already cached the metadata for this index... */
            if (metadata == null) {
                /* ... create a new metadata entry */
                metadata = new SharedClassMetaData(cs, man);
                /* Cache the metadata for this index for future use */
                sharedClassMetaDataCache.setSharedClassMetaData(index, metadata);

            }
            try {
                /* Store class in shared class cache for future use */
                sharedClassURLClasspathHelper.storeSharedClass(clazz, index);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        return clazz;
    }

    /*
     * Defines a class using the class bytes, codesource and manifest
     * obtained from the specified shared class cache. The resulting
     * class must be resolved before it can be used.  This method is
     * used only in a Shared classes context.
     */
    private Class defineClass(String name, byte[] sharedClazz, CodeSource codesource, Manifest man) throws IOException {
        int i = name.lastIndexOf('.');
        URL url = codesource.getLocation();
        if (i != -1) {
            String pkgname = name.substring(0, i);
            // Check if package already loaded.
            if (getAndVerifyPackage(pkgname, man, url) == null) {
                try {
                    if (null != man) {
                        definePackage(pkgname, man, url);
                    } else {
                        definePackage(pkgname, null, null, null, null, null, null, null);
                    }
                } catch (IllegalArgumentException iae) {
                    // https://github.com/eclipse-openj9/openj9/issues/3038
                    // Detect and ignore race between two threads defining different classes in the same package.
                    if (getAndVerifyPackage(pkgname, man, url) == null) {
                        // Should never happen
                        throw new AssertionError("Cannot find package " + pkgname);
                    }
                }
            }
        }
        /*
         * Now read the class bytes and define the class.  We don't need to call
         * storeSharedClass(), since its already in our shared class cache.
         */
        return defineClass(name, sharedClazz, 0, sharedClazz.length, codesource);
     }

    /**
     * Defines a new package by name in this ClassLoader. The attributes
     * contained in the specified Manifest will be used to obtain package
     * version and sealing information. For sealed packages, the additional
     * URL specifies the code source URL from which the package was loaded.
     *
     * @param name  the package name
     * @param man   the Manifest containing package version and sealing
     *              information
     * @param url   the code source url for the package, or null if none
     * @exception   IllegalArgumentException if the package name duplicates
     *              an existing package either in this class loader or one
     *              of its ancestors
     * @return the newly defined Package object
     */
    protected Package definePackage(String name, Manifest man, URL url)
        throws IllegalArgumentException
    {
        String specTitle = null, specVersion = null, specVendor = null;
        String implTitle = null, implVersion = null, implVendor = null;
        String sealed = null;
        URL sealBase = null;

        Attributes attr = SharedSecrets.javaUtilJarAccess()
                .getTrustedAttributes(man, name.replace('.', '/').concat("/"));
        if (attr != null) {
            specTitle   = attr.getValue(Name.SPECIFICATION_TITLE);
            specVersion = attr.getValue(Name.SPECIFICATION_VERSION);
            specVendor  = attr.getValue(Name.SPECIFICATION_VENDOR);
            implTitle   = attr.getValue(Name.IMPLEMENTATION_TITLE);
            implVersion = attr.getValue(Name.IMPLEMENTATION_VERSION);
            implVendor  = attr.getValue(Name.IMPLEMENTATION_VENDOR);
            sealed      = attr.getValue(Name.SEALED);
        }
        attr = man.getMainAttributes();
        if (attr != null) {
            if (specTitle == null) {
                specTitle = attr.getValue(Name.SPECIFICATION_TITLE);
            }
            if (specVersion == null) {
                specVersion = attr.getValue(Name.SPECIFICATION_VERSION);
            }
            if (specVendor == null) {
                specVendor = attr.getValue(Name.SPECIFICATION_VENDOR);
            }
            if (implTitle == null) {
                implTitle = attr.getValue(Name.IMPLEMENTATION_TITLE);
            }
            if (implVersion == null) {
                implVersion = attr.getValue(Name.IMPLEMENTATION_VERSION);
            }
            if (implVendor == null) {
                implVendor = attr.getValue(Name.IMPLEMENTATION_VENDOR);
            }
            if (sealed == null) {
                sealed = attr.getValue(Name.SEALED);
            }
        }
        if ("true".equalsIgnoreCase(sealed)) {
            sealBase = url;
        }
        return definePackage(name, specTitle, specVersion, specVendor,
                             implTitle, implVersion, implVendor, sealBase);
    }

    /*
     * Returns true if the specified package name is sealed according to the
     * given manifest.
     *
     * @throws SecurityException if the package name is untrusted in the manifest
     */
    private boolean isSealed(String name, Manifest man) {
        Attributes attr = SharedSecrets.javaUtilJarAccess()
                .getTrustedAttributes(man, name.replace('.', '/').concat("/"));
        String sealed = null;
        if (attr != null) {
            sealed = attr.getValue(Name.SEALED);
        }
        if (sealed == null) {
            if ((attr = man.getMainAttributes()) != null) {
                sealed = attr.getValue(Name.SEALED);
            }
        }
        return "true".equalsIgnoreCase(sealed);
    }

    /**
     * Finds the resource with the specified name on the URL search path.
     *
     * @param name the name of the resource
     * @return a {@code URL} for the resource, or {@code null}
     * if the resource could not be found, or if the loader is closed.
     */
    public URL findResource(final String name) {
        /*
         * The same restriction to finding classes applies to resources
         */
        URL url = AccessController.doPrivileged(
            new PrivilegedAction<URL>() {
                public URL run() {
                    return ucp.findResource(name, true);
                }
            }, acc);

        return url != null ? ucp.checkURL(url) : null;
    }

    /**
     * Returns an Enumeration of URLs representing all of the resources
     * on the URL search path having the specified name.
     *
     * @param name the resource name
     * @exception IOException if an I/O exception occurs
     * @return an {@code Enumeration} of {@code URL}s
     *         If the loader is closed, the Enumeration will be empty.
     */
    public Enumeration<URL> findResources(final String name)
        throws IOException
    {
        final Enumeration<URL> e = ucp.findResources(name, true);

        return new Enumeration<URL>() {
            private URL url = null;

            private boolean next() {
                if (url != null) {
                    return true;
                }
                do {
                    URL u = AccessController.doPrivileged(
                        new PrivilegedAction<URL>() {
                            public URL run() {
                                if (!e.hasMoreElements())
                                    return null;
                                return e.nextElement();
                            }
                        }, acc);
                    if (u == null)
                        break;
                    url = ucp.checkURL(u);
                } while (url == null);
                return url != null;
            }

            public URL nextElement() {
                if (!next()) {
                    throw new NoSuchElementException();
                }
                URL u = url;
                url = null;
                return u;
            }

            public boolean hasMoreElements() {
                return next();
            }
        };
    }

    /**
     * Returns the permissions for the given codesource object.
     * The implementation of this method first calls super.getPermissions
     * and then adds permissions based on the URL of the codesource.
     * <p>
     * If the protocol of this URL is "jar", then the permission granted
     * is based on the permission that is required by the URL of the Jar
     * file.
     * <p>
     * If the protocol is "file" and there is an authority component, then
     * permission to connect to and accept connections from that authority
     * may be granted. If the protocol is "file"
     * and the path specifies a file, then permission to read that
     * file is granted. If protocol is "file" and the path is
     * a directory, permission is granted to read all files
     * and (recursively) all files and subdirectories contained in
     * that directory.
     * <p>
     * If the protocol is not "file", then permission
     * to connect to and accept connections from the URL's host is granted.
     * @param codesource the codesource
     * @exception NullPointerException if {@code codesource} is {@code null}.
     * @return the permissions granted to the codesource
     */
    protected PermissionCollection getPermissions(CodeSource codesource)
    {
        PermissionCollection perms = super.getPermissions(codesource);

        URL url = codesource.getLocation();

        Permission p;
        URLConnection urlConnection;

        try {
            urlConnection = url.openConnection();
            p = urlConnection.getPermission();
        } catch (java.io.IOException ioe) {
            p = null;
            urlConnection = null;
        }

        if (p instanceof FilePermission) {
            // if the permission has a separator char on the end,
            // it means the codebase is a directory, and we need
            // to add an additional permission to read recursively
            String path = p.getName();
            if (path.endsWith(File.separator)) {
                path += "-";
                p = new FilePermission(path, SecurityConstants.FILE_READ_ACTION);
            }
        } else if ((p == null) && (url.getProtocol().equals("file"))) {
            String path = url.getFile().replace('/', File.separatorChar);
            path = ParseUtil.decode(path);
            if (path.endsWith(File.separator))
                path += "-";
            p =  new FilePermission(path, SecurityConstants.FILE_READ_ACTION);
        } else {
            /**
             * Not loading from a 'file:' URL so we want to give the class
             * permission to connect to and accept from the remote host
             * after we've made sure the host is the correct one and is valid.
             */
            URL locUrl = url;
            if (urlConnection instanceof JarURLConnection) {
                locUrl = ((JarURLConnection)urlConnection).getJarFileURL();
            }
            String host = locUrl.getHost();
            if (host != null && (host.length() > 0))
                p = new SocketPermission(host,
                                         SecurityConstants.SOCKET_CONNECT_ACCEPT_ACTION);
        }

        // make sure the person that created this class loader
        // would have this permission

        if (p != null) {
            final SecurityManager sm = System.getSecurityManager();
            if (sm != null) {
                final Permission fp = p;
                AccessController.doPrivileged(new PrivilegedAction<Void>() {
                    public Void run() throws SecurityException {
                        sm.checkPermission(fp);
                        return null;
                    }
                }, acc);
            }
            perms.add(p);
        }
        return perms;
    }

    /**
     * Creates a new instance of URLClassLoader for the specified
     * URLs and parent class loader. If a security manager is
     * installed, the {@code loadClass} method of the URLClassLoader
     * returned by this method will invoke the
     * {@code SecurityManager.checkPackageAccess} method before
     * loading the class.
     *
     * @param urls the URLs to search for classes and resources
     * @param parent the parent class loader for delegation
     * @exception  NullPointerException if {@code urls} is {@code null}.
     * @return the resulting class loader
     */
    public static URLClassLoader newInstance(final URL[] urls,
                                             final ClassLoader parent) {
        // Save the caller's context
        final AccessControlContext acc = AccessController.getContext();
        // Need a privileged block to create the class loader
        URLClassLoader ucl = AccessController.doPrivileged(
            new PrivilegedAction<URLClassLoader>() {
                public URLClassLoader run() {
                    return new FactoryURLClassLoader(urls, parent, acc);
                }
            });
        return ucl;
    }

    /**
     * Creates a new instance of URLClassLoader for the specified
     * URLs and default parent class loader. If a security manager is
     * installed, the {@code loadClass} method of the URLClassLoader
     * returned by this method will invoke the
     * {@code SecurityManager.checkPackageAccess} before
     * loading the class.
     *
     * @param urls the URLs to search for classes and resources
     * @exception  NullPointerException if {@code urls} is {@code null}.
     * @return the resulting class loader
     */
    public static URLClassLoader newInstance(final URL[] urls) {
        // Save the caller's context
        final AccessControlContext acc = AccessController.getContext();
        // Need a privileged block to create the class loader
        URLClassLoader ucl = AccessController.doPrivileged(
            new PrivilegedAction<URLClassLoader>() {
                public URLClassLoader run() {
                    return new FactoryURLClassLoader(urls, acc);
                }
            });
        return ucl;
    }

    static {
        sun.misc.SharedSecrets.setJavaNetAccess (
            new sun.misc.JavaNetAccess() {
                public URLClassPath getURLClassPath (URLClassLoader u) {
                    return u.ucp;
                }

                public String getOriginalHostName(InetAddress ia) {
                    return ia.holder.getOriginalHostName();
                }
            }
        );
        ClassLoader.registerAsParallelCapable();
    }

    final class ClassFinder implements PrivilegedExceptionAction {
        private String name;
        private ClassLoader classloader;

        public ClassFinder(String name, ClassLoader loader) {
            this.name = name;
            this.classloader = loader;
        }

        public Object run() throws ClassNotFoundException {
            String path = name.replace('.', '/').concat(".class");
            Resource res = ucp.getResource(path, false, classloader, showClassLoading(name));
            if (res != null) {
                try {
                    return defineClass(name, res);
                } catch (IOException e) {
                    throw new ClassNotFoundException(name, e);
                } catch (ClassFormatError e2) {
                    if (res.getDataError() != null) {
                        e2.addSuppressed(res.getDataError());
                    }
                    throw e2;
                }
            }
            return null;
        }
    }
}

final class FactoryURLClassLoader extends URLClassLoader {

    static {
        ClassLoader.registerAsParallelCapable();
    }

    FactoryURLClassLoader(URL[] urls, ClassLoader parent,
                          AccessControlContext acc) {
        super(urls, parent, acc);
    }

    FactoryURLClassLoader(URL[] urls, AccessControlContext acc) {
        super(urls, acc);
    }

    public final Class<?> loadClass(String name, boolean resolve)
        throws ClassNotFoundException
    {
        // First check if we have permission to access the package. This
        // should go away once we've added support for exported packages.
        SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            int i = name.lastIndexOf('.');
            if (i != -1) {
                sm.checkPackageAccess(name.substring(0, i));
            }
        }
        return super.loadClass(name, resolve);
    }
}
