/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to you under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.logging.log4j.core.appender;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.apache.logging.log4j.core.Layout;
import org.apache.logging.log4j.core.util.FileUtils;
import org.apache.logging.log4j.status.StatusLogger;

public class SecureFileManager extends OutputStreamManager {

    private static final StatusLogger LOGGER = StatusLogger.getLogger();
    private static final SecureFileManagerFactory FACTORY = new SecureFileManagerFactory();

    private final Cipher cipher;

    protected SecureFileManager(
            OutputStream os, String fileName, Layout<?> layout, boolean writeHeader, Cipher cipher) {
        super(os, fileName, layout, writeHeader);
        this.cipher = cipher;
    }

    public static SecureFileManager getFileManager(
            String fileName, boolean append, String encryptionKey, boolean enableEncryption, Layout<?> layout) {
        return (SecureFileManager)
                getManager(fileName, new FactoryData(fileName, append, encryptionKey, enableEncryption ,layout), FACTORY);
    }

    private static class FactoryData {
        private final String fileName;
        private final boolean append;
        private final String encryptionKey;
        private final Layout<?> layout;
        private final boolean enableEncryption;

        public FactoryData(String fileName, boolean append, String encryptionKey, boolean enableEncryption,
                           Layout<?> layout) {
            this.fileName = fileName;
            this.append = append;
            this.encryptionKey = encryptionKey;
            this.layout = layout;
            this.enableEncryption = enableEncryption;
        }
    }

    private static class SecureFileManagerFactory implements ManagerFactory<SecureFileManager, FactoryData> {
        @Override
        public SecureFileManager createManager(String name, FactoryData data) {
            try {
                File file = new File(data.fileName);
                FileUtils.makeParentDirs(file);
                OutputStream os = new FileOutputStream(file, data.append);

                // Initialize cipher
                Cipher cipher = initCipher(data.encryptionKey);
                if (cipher != null) {
                    os = new CipherOutputStream(os, cipher);
                }

                return new SecureFileManager(os, name, data.layout, true, cipher);
            } catch (IOException | GeneralSecurityException ex) {
                LOGGER.error("Failed to create SecureFileManager for file: {}", name, ex);
                return null;
            }
        }

        private Cipher initCipher(String key) throws GeneralSecurityException {
            SecretKey secretKey = new SecretKeySpec(getKeyBytes(key), "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return cipher;
        }

        private byte[] getKeyBytes(String key) throws NoSuchAlgorithmException {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            return sha.digest(key.getBytes());
        }
    }

    @Override
    protected void write(byte[] bytes, int offset, int length, boolean immediateFlush) {
        super.write(bytes, offset, length, immediateFlush);
    }

    @Override
    public void close() {
        super.close();
    }
}
