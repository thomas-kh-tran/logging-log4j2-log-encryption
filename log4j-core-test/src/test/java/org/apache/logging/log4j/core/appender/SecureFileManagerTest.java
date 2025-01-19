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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.apache.logging.log4j.core.layout.PatternLayout;
import org.junit.jupiter.api.Test;

/**
 * Tests {@link SecureFileManager}.
 */
class SecureFileManagerTest {

    @Test
    void testLogWritingAndEncryption() throws Exception {
        String encryptionKey = "1234567890123456";
        String iv = "1234567890123456";
        String fileName = "logs/encrypted.log";
        File logFile = new File(fileName);
        if (logFile.exists()) logFile.delete();

        SecureFileManager manager = SecureFileManager.getFileManager(
                fileName,
                true, // Append
                encryptionKey,
                iv,
                PatternLayout.createDefaultLayout(),
                true, // Enable Encryption
                false // Enable Hashing
                );

        String logMessage = "This is a test log";

        byte[] data = logMessage.getBytes();
        manager.write(data, 0, data.length, true);

        // Verify that encrypted data is written to the file
        assertTrue(logFile.exists(), "Log file should exist");
        byte[] fileData = Files.readAllBytes(logFile.toPath());
        assertNotEquals(logMessage, new String(fileData), "Log data should be encrypted");
        // Verify file is correctly decrypted
        String decryptedLog = SecureFileManager.decryptFile(fileName, encryptionKey, iv);
        assertNotEquals(decryptedLog, "Decryption should return result");
        assertEquals(logMessage, decryptedLog, "Decrypted log message should be the original message");

        // Verify for multiple log messages
        manager.write(data, 0, data.length, true);
        manager.close();
        logMessage = logMessage + logMessage;
        decryptedLog = SecureFileManager.decryptFile(fileName, encryptionKey, iv);

        assertNotEquals(decryptedLog, "Decryption should return result");
        assertEquals(logMessage, decryptedLog, "Decrypted log message should be the original messages");
    }

    @Test
    void testLogHashing() throws Exception {
        String fileName = "logs/hashed.log";
        File logFile = new File(fileName);
        if (logFile.exists()) logFile.delete();

        SecureFileManager manager = SecureFileManager.getFileManager(
                fileName,
                false, // Append
                null,
                null,
                PatternLayout.createDefaultLayout(),
                false, // Disable Encryption
                true // Enable Hashing
                );

        String logMessage = "Hashing test log";
        byte[] data = logMessage.getBytes();
        manager.write(data, 0, data.length, true);

        // Decrypt and verify hash
        Path path = Paths.get(fileName);
        String logData = new String(Files.readAllBytes(path));

        assertNotNull(logData, "Decrypted log should not be null");
        assertTrue(logData.contains(logMessage), "Decrypted log should contain the original message");
        assertTrue(logData.contains("||"), "Decrypted log should contain the hash separator");
        assertTrue(checkHashes(fileName), "Hash should match log");

        // Verify for multiple log messages
        manager.write(data, 0, data.length, true);
        manager.close();
        assertTrue(checkHashes(fileName), "Hash should match log");
    }

    @Test
    void testLogEncryptionHashing() {
        String encryptionKey = "1234567890123456";
        String iv = "1234567890123456";
        String fileName = "logs/encHashed.log";
        File logFile = new File(fileName);
        if (logFile.exists()) logFile.delete();

        SecureFileManager manager = SecureFileManager.getFileManager(
                fileName,
                false, // Append
                encryptionKey,
                iv,
                PatternLayout.createDefaultLayout(),
                true, // Enable Encryption
                true // Enable Hashing
                );

        String logMessage = "Encrypted, hashed test log";
        byte[] data = logMessage.getBytes();
        manager.write(data, 0, data.length, true);

        // Decrypt and verify hash
        String decryptedLog = SecureFileManager.decryptFile(fileName, encryptionKey, iv);

        assertNotNull(decryptedLog, "Decrypted log should not be null");
        assertTrue(decryptedLog.contains(logMessage), "Decrypted log should contain the original message");
        assertTrue(decryptedLog.contains("||"), "Decrypted log should contain the hash separator");
        assertTrue(checkHashesString(decryptedLog), "Hash should match decrypted String");

        // Verify for multiple log messages
        manager.write(data, 0, data.length, true);
        manager.close();
        decryptedLog = SecureFileManager.decryptFile(fileName, encryptionKey, iv);
        assertNotNull(decryptedLog, "Decrypted log should not be null");
        assertTrue(checkHashesString(decryptedLog), "Hash should match decrypted String");
    }

    // Helper functions
    private boolean checkHashes(String filePath) {
        try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = br.readLine()) != null) {
                // Split the line using the HASH_SEPARATOR ("||")
                int separatorIndex = line.lastIndexOf("||");
                if (separatorIndex != -1) {
                    String message = line.substring(0, separatorIndex).trim();
                    String hashWithSeparators = line.substring(separatorIndex).trim();

                    // Validate hash format
                    if (hashWithSeparators.startsWith("||")) {
                        String extractedHash = hashWithSeparators.substring(2);

                        // Compute the hash of the message
                        String computedHash = computeHash(message);

                        // Compare the computed hash with the extracted hash
                        return computedHash.equals(extractedHash);
                    }
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return false;
    }

    public boolean checkHashesString(String logContent) {
        String[] lines = logContent.split("\n");

        for (String line : lines) {
            line = line.trim();
            if (line.isEmpty()) continue;

            // Split the line using the HASH_SEPARATOR ("||")
            int separatorIndex = line.lastIndexOf("||");
            if (separatorIndex != -1) {
                String message = line.substring(0, separatorIndex).trim();
                String hashWithSeparators = line.substring(separatorIndex).trim();

                // Validate hash format
                if (hashWithSeparators.startsWith("||")) {
                    String extractedHash = hashWithSeparators.substring(2);

                    // Compute the hash of the message
                    String computedHash = computeHash(message);

                    // Compare the computed hash with the extracted hash
                    return computedHash.equals(extractedHash);
                }
            }
        }
        return false;
    }

    private String computeHash(String message) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(message.getBytes());
            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
