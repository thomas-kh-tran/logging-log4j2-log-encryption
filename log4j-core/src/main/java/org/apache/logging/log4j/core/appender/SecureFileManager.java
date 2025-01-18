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
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.logging.log4j.core.Layout;
import org.apache.logging.log4j.core.util.FileUtils;
import org.apache.logging.log4j.status.StatusLogger;

public class SecureFileManager extends OutputStreamManager {

    private static final StatusLogger LOGGER = StatusLogger.getLogger();
    private static final SecureFileManagerFactory FACTORY = new SecureFileManagerFactory();
    private static final String HASH_SEPARATOR = "||";
    private final boolean enableHashing;
    private final MessageDigest digest;

    protected SecureFileManager(
            OutputStream os, String fileName, Layout<?> layout, boolean writeHeader, boolean enableHashing) {
        super(os, fileName, layout, writeHeader);
        this.enableHashing = enableHashing;
        this.digest = initDigest(enableHashing);
    }

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

    public static SecureFileManager getFileManager(
            String fileName,
            boolean append,
            String encryptionKey,
            String iv,
            Layout<?> layout,
            boolean enableEncryption,
            boolean enableHashing) {
        return (SecureFileManager) getManager(
                fileName,
                new FactoryData(fileName, append, encryptionKey, iv, layout, enableEncryption, enableHashing),
                FACTORY);
    }

    private static class FactoryData {
        private final String fileName;
        private final boolean append;
        private final String encryptionKey;
        private final String iv;
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
                boolean enableHashing) {
            this.fileName = fileName;
            this.append = append;
            this.encryptionKey = encryptionKey;
            this.iv = iv;
            this.layout = layout;
            this.enableEncryption = enableEncryption;
            this.enableHashing = enableHashing;
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

                return new SecureFileManager(os, name, data.layout, true, data.enableHashing);
            } catch (IOException | GeneralSecurityException ex) {
                LOGGER.error("Failed to create SecureFileManager for file: {}", name, ex);
                return null;
            }
        }

        private Cipher initCipher(int mode, String key, String iv) throws GeneralSecurityException {
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            SecretKey secretKey = new SecretKeySpec(key.getBytes(), "AES");
            IvParameterSpec ivParams = new IvParameterSpec(iv.getBytes());
            cipher.init(mode, secretKey, ivParams);
            return cipher;
        }

        // Method to decrypt data and return as byte array
        private byte[] decryptToBytes(File file, String encryptionKey, String iv) {
            try {
                byte[] encryptedData = Files.readAllBytes(file.toPath());
                Cipher cipher = initCipher(Cipher.DECRYPT_MODE, encryptionKey, iv);
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
            return new String(decryptedData);
        }
    }

    /**
     * Public method to allow users to decrypt the log file and get the content as a String.
     * Example usage:
     * System.out.println(SecureFileManager.decryptFile("logs/secure.log", "yourKey", "yourIV"));
     */
    public static String decryptFile(String fileName, String encryptionKey, String iv) {
        try {
            SecureFileManagerFactory factory = new SecureFileManagerFactory();
            return factory.decryptToString(fileName, encryptionKey, iv);
        } catch (Exception e) {
            LOGGER.error("Failed to decrypt file: {}", fileName, e);
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
                byte[] hash = digest.digest(bytes);
                String combinedData = new String(bytes) + HASH_SEPARATOR + bytesToHex(hash) + HASH_SEPARATOR + '\n';
                dataToWrite = combinedData.getBytes();
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
    ////////////////////////////////////////////////////////////////////////
    /*  private static SecretKey deriveKey(String password, String salt) throws GeneralSecurityException {
            byte[] saltBytes = salt != null ? salt.getBytes() : new byte[16];
            SecureRandom random = new SecureRandom();
            random.nextBytes(saltBytes);

            KeySpec spec = new PBEKeySpec(password.toCharArray(), saltBytes, 65536, 256);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
        }
        public static void main(String[] args) throws GeneralSecurityException {
            //logger.error("Sensitive error data.");
            String iv="bG9nZW52aXJvbndhbn";
            String salt = "a9v5n38s";
            String key = "mySecretKey";
            SecretKey secretKey = deriveKey(key, salt);
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            //OutputStream os = new FileOutputStream("C:\\log4j-secure-sample\\logs\\secure-log.log", false);
            //os = new CipherOutputStream(os, cipher);
    */
    /*
    byte[] ivBytes = Base64.getDecoder().decode(iv);
    IvParameterSpec ivParams = new IvParameterSpec(ivBytes);

    cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParams);
    String decryptedLog = SecureFileManager.decryptFile("C:\\log4j-secure-sample\\logs\\secure-log.log", "mySecretKey", "a9v5n38s", "bG9nZW52aXJvbndh");
    System.out.println(decryptedLog);*/
    /*
        byte[] ivBytes = "bG9nZW52aXJvbndh".getBytes();
        IvParameterSpec ivParams = new IvParameterSpec(ivBytes);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParams);

    }*/
}
