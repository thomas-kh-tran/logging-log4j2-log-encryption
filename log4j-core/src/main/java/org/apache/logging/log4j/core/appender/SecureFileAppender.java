package org.apache.logging.log4j.core.appender;

import java.io.Serializable;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
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
    private final String encryptionAlgorithm;
    private final SecretKey secretKey;
    private final Path filePath;

    protected SecureFileAppender(
            String name,
            Layout<? extends Serializable> layout,
            Filter filter,
            boolean enableEncryption,
            String encryptionAlgorithm,
            Path filePath) {
        super(name, layout, filter, true, true, Property.EMPTY_ARRAY, null);
        this.enableEncryption = enableEncryption;
        this.encryptionAlgorithm = encryptionAlgorithm;
        this.filePath = filePath;
        this.secretKey = enableEncryption ? generateSecretKey(encryptionAlgorithm) : null;
    }

    @PluginFactory
    public static SecureFileAppender createAppender(
            @PluginAttribute("name") String name,
            @PluginAttribute("fileName") String fileName,
            @PluginElement("Layout") Layout<? extends Serializable> layout,
            @PluginElement("Filter") Filter filter,
            @PluginAttribute("enableEncryption") boolean enableEncryption,
            @PluginAttribute("encryptionAlgorithm") String encryptionAlgorithm) {

        if (layout == null) {
            layout = PatternLayout.createDefaultLayout();
        }

        Path filePath = Paths.get(fileName != null ? fileName : "logs/secure-log.log");

        return new SecureFileAppender(
                name,
                layout,
                filter,
                enableEncryption,
                encryptionAlgorithm == null ? "AES" : encryptionAlgorithm,
                filePath);
    }

    @Override
    public void append(LogEvent event) {
        try {
            byte[] messageBytes = getLayout().toByteArray(event);
            byte[] outputBytes = enableEncryption ? encrypt(messageBytes) : messageBytes;

            Files.write(filePath, outputBytes, StandardOpenOption.CREATE, StandardOpenOption.APPEND);

        } catch (Exception e) {
            if (!ignoreExceptions()) {
                throw new AppenderLoggingException("Failed to write to secure log file", e);
            }
        }
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

    private byte[] encrypt(byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance(encryptionAlgorithm);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(data);
    }
}
