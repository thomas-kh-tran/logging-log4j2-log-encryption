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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.logging.log4j.core.Layout;
import org.apache.logging.log4j.core.util.FileUtils;
import org.apache.logging.log4j.status.StatusLogger;

/**
 * A custom implementation of {@link OutputStreamManager} for the Log4j2 framework
 * that supports secure logging with encryption, hashing and salting.
 * <p>
 * This class provides functionality to:
 * <ul>
 *     <li>Encrypt log files using AES encryption in CTR mode.</li>
 *     <li>Append SHA-256 hashes to log entries for integrity verification using '||' as a separator.</li>
 *     <li>Additionally use salting to enhance hash uniqueness, appending the salt using '||' as a separator.</li>
 * </ul>
 * </p>
 * <p>
 * The class also includes utilities to decrypt encrypted log files and
 * retrieve their content.
 * </p>
 */
public class SecureFileManager extends OutputStreamManager {

    private static final StatusLogger LOGGER = StatusLogger.getLogger();
    private static final SecureFileManagerFactory FACTORY = new SecureFileManagerFactory();
    private static final String HASH_SEPARATOR = "||";
    private static final int SALT_BYTE_LENGTH = 16;
    private final boolean enableHashing;
    private final MessageDigest digest;
    private final boolean useSalt;

    /**
     * Constructs a new instance of {@link SecureFileManager}.
     *
     * @param os           The output stream used for writing logs.
     * @param filePath     The name and path of the log file.
     * @param layout       The layout to format log events.
     * @param writeHeader  Indicates whether to write a header at the beginning of the log.
     * @param enableHashing Specifies if hashing should be applied to log entries.
     * @param useSalt      Specifies if salting should be used for hashes.
     */
    protected SecureFileManager(
            OutputStream os,
            String filePath,
            Layout<?> layout,
            boolean writeHeader,
            boolean enableHashing,
            boolean useSalt) {
        super(os, filePath, layout, writeHeader);
        this.enableHashing = enableHashing;
        this.useSalt = useSalt;
        this.digest = initDigest(enableHashing);
    }

    /**
     * Initializes a {@link MessageDigest} instance for hashing if enabled.
     *
     * @param enableHashing A boolean indicator if hashing is enabled.
     * @return A {@link MessageDigest} instance or {@code null} if hashing is disabled.
     */
    private MessageDigest initDigest(boolean enableHashing) {
        if (enableHashing) {
            try {
                return MessageDigest.getInstance("SHA-256");
            } catch (NoSuchAlgorithmException e) {
                LOGGER.error("Failed to initialize SHA-256 MessageDigest.", e);
            }
        }
        return null;
    }
    /**
     * Retrieves or creates a {@link SecureFileManager} instance.
     *
     * @param filePath        The name and path of the log file.
     * @param append          Specifies whether to append to the existing file.
     * @param encryptionKey   The encryption key used for encrypting log entries.
     * @param iv              The initialization vector for AES encryption.
     * @param layout          The layout used to format log events.
     * @param enableEncryption Indicates whether encryption should be enabled.
     * @param enableHashing    Indicates whether hashing should be enabled.
     * @param useSalt         Specifies if salting should be applied to hashes.
     * @return A {@link SecureFileManager} instance or {@code null} if an error occurs.
     */
    public static SecureFileManager getFileManager(
            String filePath,
            boolean append,
            String encryptionKey,
            String iv,
            Layout<?> layout,
            boolean enableEncryption,
            boolean enableHashing,
            boolean useSalt) {
        return (SecureFileManager) getManager(
                filePath,
                new FactoryData(filePath, append, encryptionKey, iv, layout, enableEncryption, enableHashing, useSalt),
                FACTORY);
    }

    private static class FactoryData {
        private final String fileName;
        private final boolean append;
        private final String encryptionKey;
        private final String iv;
        private final boolean useSalt;
        private final Layout<?> layout;
        private final boolean enableEncryption;
        private final boolean enableHashing;

        public FactoryData(
                String fileName,
                boolean append,
                String encryptionKey,
                String iv,
                Layout<?> layout,
                boolean enableEncryption,
                boolean enableHashing,
                boolean useSalt) {
            this.fileName = fileName;
            this.append = append;
            this.encryptionKey = encryptionKey;
            this.iv = iv;
            this.layout = layout;
            this.enableEncryption = enableEncryption;
            this.enableHashing = enableHashing;
            this.useSalt = useSalt;
        }
    }

    private static class SecureFileManagerFactory implements ManagerFactory<SecureFileManager, FactoryData> {
        @Override
        public SecureFileManager createManager(String name, FactoryData data) {
            try {
                File file = new File(data.fileName);
                FileUtils.makeParentDirs(file);
                OutputStream os;
                if (data.enableEncryption && data.encryptionKey != null && !data.encryptionKey.isEmpty()) {
                    byte[] existingContent = null;

                    // Handle append logic by decrypting existing file content
                    if (data.append && file.exists()) {
                        existingContent = decryptToBytes(file, data.encryptionKey, data.iv);
                    }

                    // Prepare output stream (overwrite mode)
                    os = new FileOutputStream(file, false);
                    Cipher cipher = initCipher(Cipher.ENCRYPT_MODE, data.encryptionKey, data.iv);
                    os = new CipherOutputStream(os, cipher);
                    // If existing content is not null, re-encrypt and write it back
                    if (existingContent != null) {
                        os.write(existingContent);
                    }
                } else {
                    os = new FileOutputStream(file, data.append);
                }

                return new SecureFileManager(os, name, data.layout, true, data.enableHashing, data.useSalt);
            } catch (IOException ex) {
                LOGGER.error("Failed to create SecureFileManager for file: {}", name, ex);
                return null;
            }
        }

        private Cipher initCipher(int mode, String key, String iv) {
            try {
                Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
                SecretKey secretKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");
                IvParameterSpec ivParams = new IvParameterSpec(iv.getBytes(StandardCharsets.UTF_8));
                cipher.init(mode, secretKey, ivParams);
                return cipher;
            } catch (GeneralSecurityException e) {
                LOGGER.error("Failed. AES secretKey must be 16/32 bytes and IV 16 bytes long");
                return null;
            }
        }

        // Method to decrypt data and return as byte array
        private byte[] decryptToBytes(File file, String encryptionKey, String iv) {
            try {
                byte[] encryptedData = Files.readAllBytes(file.toPath());
                Cipher cipher = initCipher(Cipher.DECRYPT_MODE, encryptionKey, iv);
                assert cipher != null;
                return cipher.doFinal(encryptedData);
            } catch (IOException | GeneralSecurityException e) {
                LOGGER.error("Failed to decrypt file: {}", file.getName(), e);
                return null;
            }
        }

        // Method to decrypt data and return as String
        public String decryptToString(String fileName, String encryptionKey, String iv) {
            File file = new File(fileName);
            byte[] decryptedData = decryptToBytes(file, encryptionKey, iv);
            assert decryptedData != null;
            return new String(decryptedData);
        }
    }

    /**
     * Decrypts the content of an encrypted log file and returns it as a String
     *
     * @param filePath      The name and path of the encrypted log file.
     * @param encryptionKey The encryption key used for decryption.
     * @param iv            The initialization vector used for decryption.
     * @return The decrypted content of the log file, or {@code null} if decryption fails.
     */
    public static String decryptFile(String filePath, String encryptionKey, String iv) {
        try {
            SecureFileManagerFactory factory = new SecureFileManagerFactory();
            return factory.decryptToString(filePath, encryptionKey, iv);
        } catch (Exception e) {
            LOGGER.error("Failed to decrypt file: {}", filePath, e);
            return null;
        }
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    @Override
    protected void write(byte[] bytes, int offset, int length, boolean immediateFlush) {
        try {
            byte[] dataToWrite = bytes;

            // If hashing is enabled, append the hash to the data
            if (enableHashing && digest != null) {
                // Normalize line endings for consistent hashing
                int dataLength = length;
                while (dataLength > 0
                        && (bytes[offset + dataLength - 1] == '\n' || bytes[offset + dataLength - 1] == '\r')) {
                    dataLength--;
                }

                // Hash the normalized data
                byte[] normalizedData = Arrays.copyOfRange(bytes, offset, offset + dataLength);
                byte[] hash;
                byte[] saltBytes = new byte[SALT_BYTE_LENGTH];
                if (useSalt) {
                    // Generate a 16-byte salt using SecureRandom
                    SecureRandom secureRandom = new SecureRandom();
                    secureRandom.nextBytes(saltBytes);
                    // Append it to the normalized data
                    byte[] dataWithSalt = new byte[normalizedData.length + saltBytes.length];
                    System.arraycopy(normalizedData, 0, dataWithSalt, 0, normalizedData.length);
                    System.arraycopy(saltBytes, 0, dataWithSalt, normalizedData.length, saltBytes.length);
                    hash = digest.digest(dataWithSalt);
                } else {
                    // Hash without salt
                    hash = digest.digest(normalizedData);
                }

                // Build the output string with data, hash
                StringBuilder combinedDataBuilder = new StringBuilder();
                combinedDataBuilder
                        .append(new String(normalizedData, StandardCharsets.UTF_8))
                        .append(HASH_SEPARATOR)
                        .append(bytesToHex(hash));

                if (useSalt) { // optionally salt
                    // Append the Base64-encoded salt
                    String saltBase64 = Base64.getEncoder().encodeToString(saltBytes);
                    combinedDataBuilder.append(HASH_SEPARATOR).append(saltBase64);
                }

                combinedDataBuilder.append('\n');
                dataToWrite = combinedDataBuilder.toString().getBytes(StandardCharsets.UTF_8);
            }

            super.write(dataToWrite, 0, dataToWrite.length, immediateFlush);
        } catch (Exception e) {
            LOGGER.error("Failed to write hashed and encrypted log data.", e);
        }
    }

    @Override
    public void close() {
        super.close();
    }
}
