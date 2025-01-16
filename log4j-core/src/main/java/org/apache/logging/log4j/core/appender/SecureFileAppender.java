package org.apache.logging.log4j.core.appender;

import java.io.IOException;
import java.io.OutputStream;
import java.io.Serializable;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.apache.logging.log4j.core.Filter;
import org.apache.logging.log4j.core.Layout;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.config.Property;
import org.apache.logging.log4j.core.config.plugins.Plugin;
import org.apache.logging.log4j.core.config.plugins.PluginAttribute;
import org.apache.logging.log4j.core.config.plugins.PluginElement;
import org.apache.logging.log4j.core.config.plugins.PluginFactory;
import org.apache.logging.log4j.core.layout.PatternLayout;

@Plugin(name = "SecureFile", category = "Core", elementType = "appender", printObject = true)
public class SecureFileAppender extends AbstractOutputStreamAppender<FileManager> {

    private final boolean enableEncryption;
    private final boolean enableHashing;
    private final String encryptionAlgorithm;
    private final String hashAlgorithm;
    private final SecretKey secretKey;
    private final Path filePath;
    private OutputStream outputStream;

    protected SecureFileAppender(
            String name,
            Layout<? extends Serializable> layout,
            Filter filter,
            boolean ignoreExceptions,
            boolean enableEncryption,
            boolean enableHashing,
            String encryptionAlgorithm,
            String hashAlgorithm,
            Path filePath) {

        super(name, layout, filter, ignoreExceptions, true, Property.EMPTY_ARRAY, null);

        this.enableEncryption = enableEncryption;
        this.enableHashing = enableHashing;
        this.encryptionAlgorithm = encryptionAlgorithm;
        this.hashAlgorithm = hashAlgorithm;
        this.filePath = filePath;
        this.secretKey = enableEncryption ? generateSecretKey(encryptionAlgorithm) : null;
    }

    @PluginFactory
    public static SecureFileAppender createAppender(
            @PluginAttribute("name") String name,
            @PluginAttribute("fileName") String fileName,
            @PluginElement("Layout") Layout<? extends Serializable> layout,
            @PluginElement("Filter") Filter filter,
            @PluginAttribute(value = "ignoreExceptions", defaultBoolean = true) boolean ignoreExceptions,
            @PluginAttribute(value = "enableEncryption", defaultBoolean = false) boolean enableEncryption,
            @PluginAttribute(value = "enableHashing", defaultBoolean = false) boolean enableHashing,
            @PluginAttribute(value = "encryptionAlgorithm") String encryptionAlgorithm,
            @PluginAttribute(value = "hashAlgorithm") String hashAlgorithm) {


        if (fileName == null) {
            LOGGER.error("No fileName provided for SecureFileAppender");
            return null;
        }

        if (layout == null) {
            layout = PatternLayout.createDefaultLayout();
        }

        Path filePath = Paths.get(fileName);

        return new SecureFileAppender(
                name,
                layout,
                filter,
                ignoreExceptions,
                enableEncryption,
                enableHashing,
                encryptionAlgorithm == null ? "AES" : encryptionAlgorithm,
                hashAlgorithm == null ? "SHA-256" : hashAlgorithm,
                filePath);
    }

    @Override
    public void start() {
        super.start();
        try {
            Files.createDirectories(filePath.getParent());
            outputStream = Files.newOutputStream(filePath, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            LOGGER.info("SecureFileAppender started: Writing to {}", filePath.toString());
        } catch (IOException e) {
            LOGGER.error("Failed to open output stream for file: {}", filePath, e);
        }
    }

    @Override
    public void stop() {
        super.stop();
        try {
            if (outputStream != null) {
                outputStream.close();
                LOGGER.info("SecureFileAppender stopped and closed output stream.");
            }
        } catch (IOException e) {
            LOGGER.error("Error closing file output stream", e);
        }
    }

    @Override
    public void append(LogEvent event) {
        try {
            byte[] logBytes = getLayout().toByteArray(event);
            byte[] processedBytes = processLogData(logBytes);

            outputStream.write(processedBytes);
            outputStream.flush();

        } catch (Exception e) {
            if (!ignoreExceptions()) {
                throw new AppenderLoggingException("Failed to write to secure log file", e);
            }
            LOGGER.error("Failed to write log event", e);
        }
    }

    private byte[] processLogData(byte[] data) throws Exception {
        byte[] encryptedData = enableEncryption ? encryptData(data) : data;

        if (enableHashing) {
            byte[] hash = hashData(encryptedData);
            // Combine encrypted data and hash
            byte[] combined = new byte[encryptedData.length + hash.length];
            System.arraycopy(encryptedData, 0, combined, 0, encryptedData.length);
            System.arraycopy(hash, 0, combined, encryptedData.length, hash.length);
            return combined;
        }

        return encryptedData;
    }


    private byte[] hashData(byte[] data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance(hashAlgorithm);
        return digest.digest(data);
    }

    private byte[] encryptData(byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance(encryptionAlgorithm);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(data);
    }

    private SecretKey generateSecretKey(String algorithm) {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(algorithm);
            keyGen.init(256);
            return keyGen.generateKey();
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate secret key", e);
        }
    }
}
