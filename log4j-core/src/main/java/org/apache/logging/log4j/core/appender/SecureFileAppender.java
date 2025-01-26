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

import java.io.Serializable;
import org.apache.logging.log4j.core.Filter;
import org.apache.logging.log4j.core.Layout;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.config.Property;
import org.apache.logging.log4j.core.config.plugins.Plugin;
import org.apache.logging.log4j.core.config.plugins.PluginAttribute;
import org.apache.logging.log4j.core.config.plugins.PluginElement;
import org.apache.logging.log4j.core.config.plugins.PluginFactory;
import org.apache.logging.log4j.core.layout.PatternLayout;

/**
 * A custom Log4j2 appender that writes log events to a file securely using optionally encryption, hashing and salting.
 * <p>
 * This appender integrates with {@link SecureFileManager} to provide the following features:
 * <ul>
 *     <li>Encrypt log entries using AES encryption in CTR mode.</li>
 *     <li>Append cryptographic hashes for log integrity verification.</li>
 *     <li>Salting to enhance hash uniqueness.</li>
 * </ul>
 * </p>
 * <p>
 * Configuration example in Log4j2 XML configuration:
 * </p>
 * <pre>
 * {@code
 * <Appenders>
 *     <SecureFileAppender name="SecureFileAppender" fileName="logs/secure.log"
 *                         encryptionKey="AESCompatibleKey16/24/32ByteLength00" iv="16byteIV00000000" append="true"
 *                         enableEncryption="true" enableHashing="true" useSalt="true">
 *         <PatternLayout pattern="%d{ISO8601} %m%n" />
 *     </SecureFileAppender>
 * </Appenders>
 * }
 * </pre>
 */
@Plugin(name = "SecureFileAppender", category = "Core", elementType = "appender", printObject = true)
public class SecureFileAppender extends AbstractAppender {

    public static final int AES128KeyLength = 16;
    public static final int AES192KeyLength = 24;
    public static final int AES256KeyLength = 32;
    public static final int IVLength = 16;
    private final SecureFileManager manager;

    protected SecureFileAppender(
            String name,
            Filter filter,
            Layout<? extends Serializable> layout,
            boolean ignoreExceptions,
            SecureFileManager manager) {
        super(name, filter, layout, ignoreExceptions, Property.EMPTY_ARRAY);
        this.manager = manager;
    }

    @Override
    public void append(LogEvent event) {
        byte[] data = getLayout().toByteArray(event);
        manager.write(data, 0, data.length, true);
    }

    /**
     * Factory method to create a new instance of {@code SecureFileAppender}.
     * <p>
     * This method performs validation on the provided configuration attributes to ensure that
     * encryption and hashing are properly configured.
     * </p>
     *
     * @param name            The name of the appender.
     * @param fileName        The name of the file where logs will be written.
     * @param iv              The initialization vector for AES encryption (16 bytes), required if encrypting.
     * @param encryptionKey   The AES encryption key (16, 24, or 32 bytes), required if encrypting.
     * @param append          Whether to append to the existing file (default: {@code true}).
     * @param enableEncryption Whether encryption should be enabled (default: {@code false}).
     * @param enableHashing    Whether hashing should be enabled for log entries (default: {@code false}).
     * @param useSalt         Whether salting should be used for hashes (default: {@code false}).
     * @param layout          The layout to format log entries. If {@code null}, a default layout is used.
     * @param filter          The filter to control event processing.
     * @return A new instance of {@code SecureFileAppender}, or {@code null} if validation fails.
     */
    @PluginFactory
    public static SecureFileAppender createAppender(
            @PluginAttribute("name") String name,
            @PluginAttribute("fileName") String fileName,
            @PluginAttribute("iv") String iv,
            @PluginAttribute("encryptionKey") String encryptionKey,
            @PluginAttribute(value = "append", defaultBoolean = true) boolean append,
            @PluginAttribute(value = "enableEncryption", defaultBoolean = false) boolean enableEncryption,
            @PluginAttribute(value = "enableHashing", defaultBoolean = false) boolean enableHashing,
            @PluginAttribute(value = "useSalt", defaultBoolean = false) boolean useSalt,
            @PluginElement("Layout") Layout<? extends Serializable> layout,
            @PluginElement("Filter") Filter filter) {

        // Verify attributes
        if (name == null || name.isEmpty()) {
            LOGGER.error("No name provided for SecureFileAppender");
            return null;
        }

        if (fileName == null || fileName.isEmpty()) {
            LOGGER.error("No fileName provided for SecureFileAppender");
            return null;
        }

        if (enableEncryption) {
            if (encryptionKey == null) {
                LOGGER.error("Encryption enabled but no AES compatible SecretKey provided");
                return null;
            }
            int keyLength = encryptionKey.length();
            if (keyLength != AES128KeyLength && keyLength != AES192KeyLength && keyLength != AES256KeyLength) {
                LOGGER.error("Encryption enabled but SecretKey is not of compatible length. (16,24,32 bytes)");
                return null;
            }
            if (iv == null) {
                LOGGER.error("Encryption enabled but no 16 byte IV provided");
                return null;
            }
            if (iv.length() != IVLength) {
                LOGGER.error("Encryption enabled but IV is not of length 16 bytes. ");
                return null;
            }
        }
        if (enableHashing && !useSalt) {
            LOGGER.info("Using no salt for hashing.");
        }

        if (layout == null) {
            layout = PatternLayout.createDefaultLayout();
        }

        SecureFileManager manager = SecureFileManager.getFileManager(
                fileName, append, encryptionKey, iv, layout, enableEncryption, enableHashing, useSalt);
        return new SecureFileAppender(name, filter, layout, true, manager);
    }

    @Override
    public void stop() {
        super.stop();
        manager.close();
    }
}
