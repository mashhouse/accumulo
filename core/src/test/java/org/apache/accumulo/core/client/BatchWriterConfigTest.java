/**
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.accumulo.core.client;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.concurrent.TimeUnit;

import org.junit.Test;

/**
 * 
 */
public class BatchWriterConfigTest {
  
  @Test
  public void testReasonableDefaults() {
    long expectedMaxMemory = 50 * 1024 * 1024l;
    long expectedMaxLatency = 120000l;
    long expectedTimeout = Long.MAX_VALUE;
    int expectedMaxWriteThreads = 3;
    
    BatchWriterConfig defaults = new BatchWriterConfig();
    assertEquals(expectedMaxMemory, defaults.getMaxMemory());
    assertEquals(expectedMaxLatency, defaults.getMaxLatency(TimeUnit.MILLISECONDS));
    assertEquals(expectedTimeout, defaults.getTimeout(TimeUnit.MILLISECONDS));
    assertEquals(expectedMaxWriteThreads, defaults.getMaxWriteThreads());
  }
  
  @Test
  public void testOverridingDefaults() {
    BatchWriterConfig bwConfig = new BatchWriterConfig();
    bwConfig.setMaxMemory(1123581321l);
    bwConfig.setMaxLatency(22, TimeUnit.HOURS);
    bwConfig.setTimeout(33, TimeUnit.DAYS);
    bwConfig.setMaxWriteThreads(42);
    
    assertEquals(1123581321l, bwConfig.getMaxMemory());
    assertEquals(22 * 60 * 60 * 1000l, bwConfig.getMaxLatency(TimeUnit.MILLISECONDS));
    assertEquals(33 * 24 * 60 * 60 * 1000l, bwConfig.getTimeout(TimeUnit.MILLISECONDS));
    assertEquals(42, bwConfig.getMaxWriteThreads());
  }
  
  @Test
  public void testZeroTimeoutAndLatency() {
    BatchWriterConfig bwConfig = new BatchWriterConfig();
    bwConfig.setMaxLatency(0, TimeUnit.MILLISECONDS);
    bwConfig.setTimeout(0, TimeUnit.MILLISECONDS);
    
    assertEquals(Long.MAX_VALUE, bwConfig.getMaxLatency(TimeUnit.MILLISECONDS));
    assertEquals(Long.MAX_VALUE, bwConfig.getTimeout(TimeUnit.MILLISECONDS));
  }
  
  @Test(expected = IllegalArgumentException.class)
  public void testMaxMemoryTooLow() {
    BatchWriterConfig bwConfig = new BatchWriterConfig();
    bwConfig.setMaxMemory(1024 - 1);
  }
  
  @Test(expected = IllegalArgumentException.class)
  public void testNegativeMaxLatency() {
    BatchWriterConfig bwConfig = new BatchWriterConfig();
    bwConfig.setMaxLatency(-1, TimeUnit.DAYS);
  }
  
  @Test(expected = IllegalArgumentException.class)
  public void testNegativeTimeout() {
    BatchWriterConfig bwConfig = new BatchWriterConfig();
    bwConfig.setTimeout(-1, TimeUnit.DAYS);
  }
  
  @Test(expected = IllegalArgumentException.class)
  public void testZeroMaxWriteThreads() {
    BatchWriterConfig bwConfig = new BatchWriterConfig();
    bwConfig.setMaxWriteThreads(0);
  }
  
  @Test(expected = IllegalArgumentException.class)
  public void testNegativeMaxWriteThreads() {
    BatchWriterConfig bwConfig = new BatchWriterConfig();
    bwConfig.setMaxWriteThreads(-1);
  }
  
  @Test
  public void testSerialize() throws IOException {
    // make sure we aren't testing defaults
    final BatchWriterConfig bwDefaults = new BatchWriterConfig();
    assertNotEquals(7654321l, bwDefaults.getMaxLatency(TimeUnit.MILLISECONDS));
    assertNotEquals(9898989l, bwDefaults.getTimeout(TimeUnit.MILLISECONDS));
    assertNotEquals(42, bwDefaults.getMaxWriteThreads());
    assertNotEquals(1123581321l, bwDefaults.getMaxMemory());
    
    // test setting all fields
    BatchWriterConfig bwConfig = new BatchWriterConfig();
    bwConfig.setMaxLatency(7654321l, TimeUnit.MILLISECONDS);
    bwConfig.setTimeout(9898989l, TimeUnit.MILLISECONDS);
    bwConfig.setMaxWriteThreads(42);
    bwConfig.setMaxMemory(1123581321l);
    byte[] bytes = createBytes(bwConfig);
    checkBytes(bwConfig, bytes);
    
    // test human-readable serialization
    bwConfig = new BatchWriterConfig();
    bwConfig.setMaxWriteThreads(42);
    bytes = createBytes(bwConfig);
    assertEquals("     i#maxWriteThreads=42", new String(bytes, Charset.forName("UTF-8")));
    checkBytes(bwConfig, bytes);
    
    // test human-readable with 2 fields
    bwConfig = new BatchWriterConfig();
    bwConfig.setMaxWriteThreads(24);
    bwConfig.setTimeout(3, TimeUnit.SECONDS);
    bytes = createBytes(bwConfig);
    assertEquals("     v#maxWriteThreads=24,timeout=3000", new String(bytes, Charset.forName("UTF-8")));
    checkBytes(bwConfig, bytes);
  }
  
  private byte[] createBytes(BatchWriterConfig bwConfig) throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    bwConfig.write(new DataOutputStream(baos));
    return baos.toByteArray();
  }
  
  private void checkBytes(BatchWriterConfig bwConfig, byte[] bytes) throws IOException {
    ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
    BatchWriterConfig createdConfig = new BatchWriterConfig();
    createdConfig.readFields(new DataInputStream(bais));
    
    assertEquals(bwConfig.getMaxMemory(), createdConfig.getMaxMemory());
    assertEquals(bwConfig.getMaxLatency(TimeUnit.MILLISECONDS), createdConfig.getMaxLatency(TimeUnit.MILLISECONDS));
    assertEquals(bwConfig.getTimeout(TimeUnit.MILLISECONDS), createdConfig.getTimeout(TimeUnit.MILLISECONDS));
    assertEquals(bwConfig.getMaxWriteThreads(), createdConfig.getMaxWriteThreads());
  }
  
}