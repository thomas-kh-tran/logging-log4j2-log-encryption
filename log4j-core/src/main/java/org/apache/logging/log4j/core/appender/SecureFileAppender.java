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

@Plugin(name = "SecureFileAppender", category = "Core", elementType = "appender", printObject = true)
public class SecureFileAppender extends AbstractAppender {

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

        SecureFileManager manager = SecureFileManager.getFileManager(
                fileName, append, encryptionKey, iv, layout, enableEncryption, enableHashing);
        return new SecureFileAppender(name, filter, layout, true, manager);
    }

    @Override
    public void stop() {
        super.stop();
        manager.close();
    }
}
