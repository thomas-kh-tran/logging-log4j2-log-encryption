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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.apache.logging.log4j.core.Layout;
import org.apache.logging.log4j.core.config.DefaultConfiguration;
import org.apache.logging.log4j.core.layout.PatternLayout;
import org.junit.jupiter.api.Test;

/**
 * Tests {@link SecureFileAppender}.
 */
class SecureFileAppenderTest {

    @Test
    void testAppenderInitialization() {
        new DefaultConfiguration();
        Layout<String> layout = PatternLayout.createDefaultLayout();

        SecureFileAppender appender = SecureFileAppender.createAppender(
                "TestAppender",
                "logs/test.log",
                null, // not implemented
                "1234567890123456", // IV 16 bytes
                "12345678901234561234567890123456", // AES compatible byte length best 32 bit
                false, // Append
                true, // encryption
                true, // hashing
                layout,
                null);

        assertNotNull(appender, "Appender should initialize correctly");
        assertEquals("TestAppender", appender.getName(), "Appender name should match");
        assertTrue(appender.isInitialized());
    }

    @Test
    void testErrorNoKeySecureFileAppender() {
        new DefaultConfiguration();
        Layout<String> layout = PatternLayout.createDefaultLayout();

        SecureFileAppender appender = SecureFileAppender.createAppender(
                "TestAppender",
                "logs/test.log",
                null, // not implemented
                "1234567890123456", // IV 16 bytes
                null, // AES compatible byte length best 32 bit
                false, // Append
                true, // encryption
                true, // hashing
                layout,
                null);
        assertNull(appender, "Appender should NOT initialize correctly");
    }

    @Test
    void testErrorKeyLengthSecureFileAppender() {
        new DefaultConfiguration();
        Layout<String> layout = PatternLayout.createDefaultLayout();

        SecureFileAppender appender = SecureFileAppender.createAppender(
                "TestAppender",
                "logs/test.log",
                null, // not implemented
                "1234567890123456", // IV 16 bytes
                "", // AES compatible byte length best 32 bit
                false, // Append
                true, // encryption
                true, // hashing
                layout,
                null);
        assertNull(appender, "Appender should NOT initialize correctly");
    }

    @Test
    void testErrorNoIVLengthSecureFileAppender() {
        new DefaultConfiguration();
        Layout<String> layout = PatternLayout.createDefaultLayout();

        SecureFileAppender appender = SecureFileAppender.createAppender(
                "TestAppender",
                "logs/test.log",
                null, // not implemented
                "", // IV 16 bytes
                "12345678901234561234567890123456", // AES compatible byte length best 32 bit
                false, // Append
                true, // encryption
                true, // hashing
                layout,
                null);
        assertNull(appender, "Appender should NOT initialize correctly");
    }

    @Test
    void testErrorNoIVSecureFileAppender() {
        new DefaultConfiguration();
        Layout<String> layout = PatternLayout.createDefaultLayout();

        SecureFileAppender appender = SecureFileAppender.createAppender(
                "TestAppender",
                "logs/test.log",
                null, // not implemented
                null, // IV 16 bytes
                "12345678901234561234567890123456", // AES compatible byte length best 32 bit
                false, // Append
                true, // encryption
                true, // hashing
                layout,
                null);
        assertNull(appender, "Appender should NOT initialize correctly");
    }

    @Test
    void testErrorFileNameEmptySecureFileAppender() {
        new DefaultConfiguration();
        Layout<String> layout = PatternLayout.createDefaultLayout();

        SecureFileAppender appender = SecureFileAppender.createAppender(
                "TestAppender",
                "",
                null, // not implemented
                "1234567890123456", // IV 16 bytes
                "12345678901234561234567890123456", // AES compatible byte length best 32 bit
                false, // Append
                true, // encryption
                true, // hashing
                layout,
                null);
        assertNull(appender, "Appender should NOT initialize correctly");
    }

    @Test
    void testErrorFileNameNullSecureFileAppender() {
        new DefaultConfiguration();
        Layout<String> layout = PatternLayout.createDefaultLayout();

        SecureFileAppender appender = SecureFileAppender.createAppender(
                "TestAppender",
                null,
                null, // not implemented
                "1234567890123456", // IV 16 bytes
                "12345678901234561234567890123456", // AES compatible byte length best 32 bit
                false, // Append
                true, // encryption
                true, // hashing
                layout,
                null);
        assertNull(appender, "Appender should NOT initialize correctly");
    }

    @Test
    void testErrorNameEmptySecureFileAppender() {
        new DefaultConfiguration();
        Layout<String> layout = PatternLayout.createDefaultLayout();

        SecureFileAppender appender = SecureFileAppender.createAppender(
                "",
                "logs/test.log",
                null, // not implemented
                "1234567890123456", // IV 16 bytes
                "12345678901234561234567890123456", // AES compatible byte length best 32 bit
                false, // Append
                true, // encryption
                true, // hashing
                layout,
                null);
        assertNull(appender, "Appender should NOT initialize correctly");
    }

    @Test
    void testErrorNameNullSecureFileAppender() {
        new DefaultConfiguration();
        Layout<String> layout = PatternLayout.createDefaultLayout();

        SecureFileAppender appender = SecureFileAppender.createAppender(
                null,
                "logs/test.log",
                null, // not implemented
                "1234567890123456", // IV 16 bytes
                "12345678901234561234567890123456", // AES compatible byte length best 32 bit
                false, // Append
                true, // encryption
                true, // hashing
                layout,
                null);
        assertNull(appender, "Appender should NOT initialize correctly");
    }
}
