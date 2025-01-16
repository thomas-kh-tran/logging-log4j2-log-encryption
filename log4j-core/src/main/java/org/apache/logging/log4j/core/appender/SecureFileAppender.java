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
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
// import java.nio.file.*;
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
import org.apache.logging.log4j.core.util.SecurityUtils;

@Plugin(name = "SecureFile", category = "Core", elementType = "appender", printObject = true)
public class SecureFileAppender extends AbstractAppender {

    private final boolean enableEncryption;
    private final boolean enableHashing;
    private final String encryptionAlgorithm;
    private final String hashAlgorithm;
    private final SecretKey secretKey;

    protected SecureFileAppender(
            String name,
            Layout<? extends Serializable> layout,
            Filter filter,
            boolean enableEncryption,
            boolean enableHashing,
            String encryptionAlgorithm,
            String hashAlgorithm) {
        super(name, filter, layout, true, Property.EMPTY_ARRAY);
        this.enableEncryption = enableEncryption;
        this.enableHashing = enableHashing;
        this.encryptionAlgorithm = encryptionAlgorithm;
        this.hashAlgorithm = hashAlgorithm;
        this.secretKey = enableEncryption ? SecurityUtils.generateSecretKey(encryptionAlgorithm) : null;
    }

    @PluginFactory
    public static SecureFileAppender createAppender(
            @PluginAttribute("name") String name,
            @PluginElement("Layout") Layout<? extends Serializable> layout,
            @PluginElement("Filter") Filter filter,
            @PluginAttribute("enableEncryption") boolean enableEncryption,
            @PluginAttribute("enableHashing") boolean enableHashing,
            @PluginAttribute("encryptionAlgorithm") String encryptionAlgorithm,
            @PluginAttribute("hashAlgorithm") String hashAlgorithm) {

        if (layout == null) {
            layout = PatternLayout.createDefaultLayout();
        }

        return new SecureFileAppender(
                name,
                layout,
                filter,
                enableEncryption,
                enableHashing,
                encryptionAlgorithm == null ? "AES" : encryptionAlgorithm,
                hashAlgorithm == null ? "SHA-256" : hashAlgorithm);
    }

    @Override
    public void append(LogEvent event) {
        try {
            String logMessage = new String(getLayout().toByteArray(event));
            byte[] processedMessage = logMessage.getBytes();

            if (enableHashing) {
                processedMessage = SecurityUtils.hashMessage(processedMessage, hashAlgorithm);
            }

            if (enableEncryption) {
                processedMessage = SecurityUtils.encryptMessage(processedMessage, secretKey, encryptionAlgorithm);
            }

            // Write the processed log to file
            Files.write(
                    Paths.get("logs/secure-log.log"),
                    processedMessage,
                    StandardOpenOption.APPEND,
                    StandardOpenOption.CREATE);

        } catch (Exception e) {
            LOGGER.error("Failed to process log event", e);
        }
    }
}
