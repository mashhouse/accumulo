/*
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
package org.apache.accumulo.core.util;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.apache.hadoop.io.Text;

public class ByteBufferUtil {
  public static byte[] toBytes(ByteBuffer buffer) {
    if (buffer == null)
      return null;
    return Arrays.copyOfRange(buffer.array(), buffer.position(), buffer.limit());
  }
  
  public static List<ByteBuffer> toByteBuffers(Collection<byte[]> bytesList) {
    if (bytesList == null)
      return null;
    ArrayList<ByteBuffer> result = new ArrayList<ByteBuffer>();
    for (byte[] bytes : bytesList) {
      result.add(ByteBuffer.wrap(bytes));
    }
    return result;
  }
  
  /**
   * Provides an immutable view of a list of byte buffers, representing the same bytes. This does not protect against modifying the underlying byte arrays.
   */
  public static List<ByteBuffer> toImmutableByteBufferList(Collection<byte[]> bytesList) {
    if (bytesList == null)
      return null;
    ArrayList<ByteBuffer> result = new ArrayList<ByteBuffer>();
    for (byte[] bytes : bytesList) {
      result.add(ByteBuffer.wrap(bytes));
    }
    return Collections.unmodifiableList(result);
  }
  
  public static List<byte[]> toBytesList(Collection<ByteBuffer> bytesList) {
    if (bytesList == null)
      return null;
    ArrayList<byte[]> result = new ArrayList<byte[]>();
    for (ByteBuffer bytes : bytesList) {
      result.add(toBytes(bytes));
    }
    return result;
  }
  
  public static Text toText(ByteBuffer bytes) {
    if (bytes == null)
      return null;
    Text result = new Text();
    result.set(bytes.array(), bytes.position(), bytes.remaining());
    return result;
  }
  
  public static String toString(ByteBuffer bytes) {
    return new String(bytes.array(), bytes.position(), bytes.remaining());
  }
}
