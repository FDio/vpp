/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.fd.vpp.jvpp;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Utility class for loading JNI libraries.
 */
public final class NativeLibraryLoader {

    private static final Logger LOG = Logger.getLogger(NativeLibraryLoader.class.getName());

    private NativeLibraryLoader() {
        throw new UnsupportedOperationException("This utility class cannot be instantiated.");
    }

    /**
     * Loads JNI library using class loader of the given class.
     *
     * @param libName name of the library to be loaded
     */
    public static void loadLibrary(final String libName, final Class clazz) throws IOException {
        java.util.Objects.requireNonNull(libName, "libName should not be null");
        java.util.Objects.requireNonNull(clazz, "clazz should not be null");
        try (final InputStream is = clazz.getResourceAsStream('/' + libName)) {
            if (is == null) {
                throw new IOException("Failed to open library resource " + libName);
            }
            loadStream(libName, is);
        }
    }

    private static void loadStream(final String libName, final InputStream is) throws IOException {
        final Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rwxr-x---");
        final Path p = Files.createTempFile(libName, null, PosixFilePermissions.asFileAttribute(perms));
        try {
            Files.copy(is, p, StandardCopyOption.REPLACE_EXISTING);
            Runtime.getRuntime().load(p.toString());
        } catch (Exception e) {
            throw new IOException("Failed to load library " + p, e);
        } finally {
            try {
                Files.deleteIfExists(p);
            } catch (IOException e) {
                LOG.log(Level.WARNING, String.format("Failed to delete temporary file %s.", p), e);
            }
        }
    }
}
