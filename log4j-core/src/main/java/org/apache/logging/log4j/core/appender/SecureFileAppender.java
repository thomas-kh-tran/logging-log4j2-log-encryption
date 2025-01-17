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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.apache.logging.log4j.core.Filter;
import org.apache.logging.log4j.core.Layout;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.config.Property;
import org.apache.logging.log4j.core.config.plugins.Plugin;
import org.apache.logging.log4j.core.config.plugins.PluginAttribute;
import org.apache.logging.log4j.core.config.plugins.PluginElement;
import org.apache.logging.log4j.core.config.plugins.PluginFactory;
import org.apache.logging.log4j.core.layout.PatternLayout;

@Plugin(name = "SecureFileAppender", category = "Core", elementType = "appender", printObject = true)
public class SecureFileAppender extends AbstractAppender {

    private final SecureFileManager manager;
    private final boolean enableHashing;
    private final boolean enableEncryption;
    private final MessageDigest digest;

    protected SecureFileAppender(
            String name,
            Filter filter,
            Layout<? extends Serializable> layout,
            boolean ignoreExceptions,
            SecureFileManager manager,
            boolean enableEncryption,
            boolean enableHashing) {
        super(name, filter, layout, ignoreExceptions, Property.EMPTY_ARRAY);
        this.manager = manager;
        this.enableEncryption = enableEncryption;
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

    @Override
    public void append(LogEvent event) {
        byte[] data = getLayout().toByteArray(event);
        if (enableHashing && digest != null) {
            byte[] hash = digest.digest(data);
            // Create a new array that includes data, hash, and the newline character
            byte[] combined = new byte[data.length + hash.length + 1]; // +1 for the newline
            System.arraycopy(data, 0, combined, 0, data.length);
            System.arraycopy(hash, 0, combined, data.length, hash.length);
            combined[combined.length - 1] = '\n'; // Add newline at the end
            manager.write(combined, 0, combined.length, true);
        } else {
            manager.write(data, 0, data.length, true);
        }
    }

    @PluginFactory
    public static SecureFileAppender createAppender(
            @PluginAttribute("name") String name,
            @PluginAttribute("fileName") String fileName,
            @PluginAttribute("salt") String salt,
            @PluginAttribute("iv") String iv,
            @PluginAttribute("encryptionKey") String encryptionKey,
            @PluginAttribute(value = "append", defaultBoolean = true) boolean append,
            @PluginAttribute(value = "enableEncryption", defaultBoolean = false) boolean enableEncryption,
            @PluginAttribute(value = "enableHashing", defaultBoolean = false) boolean enableHashing,
            @PluginElement("Layout") Layout<? extends Serializable> layout,
            @PluginElement("Filter") Filter filter) {

        if (name == null) {
            LOGGER.error("No name provided for SecureFileAppender");
            return null;
        }

        if (fileName == null) {
            LOGGER.error("No fileName provided for SecureFileAppender");
            return null;
        }

        if (layout == null) {
            layout = PatternLayout.createDefaultLayout();
        }

        SecureFileManager manager =
                SecureFileManager.getFileManager(fileName, append, encryptionKey, iv, layout, enableEncryption);
        return new SecureFileAppender(name, filter, layout, true, manager, enableEncryption, enableHashing);
    }

    @Override
    public void stop() {
        super.stop();
        manager.close();
    }

}
