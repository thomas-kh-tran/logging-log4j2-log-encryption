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
import java.nio.charset.StandardCharsets;
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
                fileName,           // log
                true,               // Append
                encryptionKey,      // SecretKey
                iv,                 // IV
                null,               // Salt
                PatternLayout.createDefaultLayout(),
                true, // Enable Encryption
                false               // Enable Hashing
                );

        String logMessage = "This is a test log";

        byte[] data = logMessage.getBytes(StandardCharsets.UTF_8);
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
                false,
                null,
                null,
                null,
                PatternLayout.createDefaultLayout(),
                false,
                true
                );

        String logMessage = "Hashing test log";
        byte[] data = logMessage.getBytes(StandardCharsets.UTF_8);
        manager.write(data, 0, data.length, true);

        // Decrypt and verify hash
        Path path = Paths.get(fileName);
        String logData = new String(Files.readAllBytes(path));

        assertNotNull(logData, "Decrypted log should not be null");
        assertTrue(logData.contains(logMessage), "Decrypted log should contain the original message");
        assertTrue(logData.contains("||"), "Decrypted log should contain the hash separator");
        assertTrue(checkHashes(fileName, false), "Hash should match log");

        // Verify for multiple log messages
        manager.write(data, 0, data.length, true);
        manager.close();
        assertTrue(checkHashes(fileName, false), "Hash should match log");
    }
    @Test
    void testLogSaltHashing() throws Exception {
        String fileName = "logs/hashed.log";
        String salt = "salt";
        File logFile = new File(fileName);
        if (logFile.exists()) logFile.delete();

        SecureFileManager manager = SecureFileManager.getFileManager(
                fileName,
                false,
                null,
                null,
                salt,
                PatternLayout.createDefaultLayout(),
                false,
                true
        );

        String logMessage = "Hashing test log";
        byte[] data = logMessage.getBytes(StandardCharsets.UTF_8);
        manager.write(data, 0, data.length, true);

        // Decrypt and verify hash
        Path path = Paths.get(fileName);
        String logData = new String(Files.readAllBytes(path));

        assertNotNull(logData, "Decrypted log should not be null");
        assertTrue(logData.contains(logMessage), "Decrypted log should contain the original message");
        assertTrue(logData.contains("||"), "Decrypted log should contain the hash separator");
        assertTrue(checkHashes(fileName, true), "Hash should match log");

        // Verify for multiple log messages
        manager.write(data, 0, data.length, true);
        manager.close();
        assertTrue(checkHashes(fileName, true), "Hash should match log");
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
                false,
                encryptionKey,
                iv,
                null,
                PatternLayout.createDefaultLayout(),
                true,
                true
                );

        String logMessage = "Encrypted, hashed test log";
        byte[] data = logMessage.getBytes(StandardCharsets.UTF_8);
        manager.write(data, 0, data.length, true);

        // Decrypt and verify hash
        String decryptedLog = SecureFileManager.decryptFile(fileName, encryptionKey, iv);

        assertNotNull(decryptedLog, "Decrypted log should not be null");
        assertTrue(decryptedLog.contains(logMessage), "Decrypted log should contain the original message");
        assertTrue(decryptedLog.contains("||"), "Decrypted log should contain the hash separator");
        assertTrue(checkHashesString(decryptedLog, false), "Hash should match decrypted String");

        // Verify for multiple log messages
        manager.write(data, 0, data.length, true);
        manager.close();
        decryptedLog = SecureFileManager.decryptFile(fileName, encryptionKey, iv);
        assertNotNull(decryptedLog, "Decrypted log should not be null");
        assertTrue(checkHashesString(decryptedLog, false), "Hash should match decrypted String");
    }

    @Test
    void testLogEncryptionSaltHashing() {
        String encryptionKey = "1234567890123456";
        String iv = "1234567890123456";
        String fileName = "logs/encHashed.log";
        String salt = "salt";
        File logFile = new File(fileName);
        if (logFile.exists()) logFile.delete();

        SecureFileManager manager = SecureFileManager.getFileManager(
                fileName,
                false,
                encryptionKey,
                iv,
                salt,
                PatternLayout.createDefaultLayout(),
                true,
                true
        );

        String logMessage = "Encrypted, hashed test log";
        byte[] data = logMessage.getBytes(StandardCharsets.UTF_8);
        manager.write(data, 0, data.length, true);

        // Decrypt and verify hash
        String decryptedLog = SecureFileManager.decryptFile(fileName, encryptionKey, iv);

        assertNotNull(decryptedLog, "Decrypted log should not be null");
        assertTrue(decryptedLog.contains(logMessage), "Decrypted log should contain the original message");
        assertTrue(decryptedLog.contains("||"), "Decrypted log should contain the hash separator");
        assertTrue(checkHashesString(decryptedLog, true), "Hash should match decrypted String");

        // Verify for multiple log messages
        manager.write(data, 0, data.length, true);
        manager.close();
        decryptedLog = SecureFileManager.decryptFile(fileName, encryptionKey, iv);
        assertNotNull(decryptedLog, "Decrypted log should not be null");
        assertTrue(checkHashesString(decryptedLog, true), "Hash should match decrypted String");
    }
    // Helper functions
    private boolean checkHashes(String filePath, boolean useSalt) {
        try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = br.readLine()) != null) {
                // Split the line using the HASH_SEPARATOR ("||")
                String[] parts = line.split("\\|\\|");

                // Ensure the line has the expected number of parts
                if ((useSalt && parts.length == 3) || (!useSalt && parts.length == 2)) {
                    String message = parts[0].trim();
                    String extractedHash = parts[1].trim();
                    String salt = useSalt ? parts[2].trim() : "";

                    // Compute the hash using the message and salt (if applicable)
                    String computedHash = useSalt ? computeHash(message+salt) : computeHash(message);

                    // Compare the computed hash with the extracted hash
                    if (!computedHash.equals(extractedHash)) {
                        return false; // Return false if any line does not match
                    }
                } else {
                    // Invalid format: log or handle appropriately
                    return false;
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
            return false; // Return false if an exception occurs
        }
        return true; // Return true if all hashes match
    }


    public boolean checkHashesString(String logContent, boolean useSalt) {
        String[] lines = logContent.split("\n");

        for (String line : lines) {
            line = line.trim();
            if (line.isEmpty()) continue;

            // Split the line using the HASH_SEPARATOR ("||")
            String[] parts = line.split("\\|\\|");

            // Ensure the line has the expected number of parts
            if ((useSalt && parts.length == 3) || (!useSalt && parts.length == 2)) {
                String message = parts[0].trim();
                String extractedHash = parts[1].trim();
                String salt = useSalt ? parts[2].trim() : "";

                // Compute the hash using the message and salt (if applicable)
                String computedHash = useSalt ? computeHash(message+salt) : computeHash(message);

                // Compare the computed hash with the extracted hash
                if (!computedHash.equals(extractedHash)) {
                    return false; // Return false if any line does not match
                }
            } else {
                // Invalid format: log or handle appropriately
                return false;
            }
        }
        return true;
    }

    private String computeHash(String message) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(message.getBytes(StandardCharsets.UTF_8));
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
