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
package org.apache.accumulo.core.client.admin;

import java.util.List;
import java.util.Map;

import org.apache.accumulo.core.client.AccumuloException;
import org.apache.accumulo.core.client.AccumuloSecurityException;

/**
 * 
 */
public interface InstanceOperations {
  
  /**
   * Sets an instance property in zookeeper. Tablet servers will pull this setting and override the equivalent setting in accumulo-site.xml
   * 
   * @param property
   *          the name of a per-table property
   * @param value
   *          the value to set a per-table property to
   * @throws AccumuloException
   *           if a general error occurs
   * @throws AccumuloSecurityException
   *           if the user does not have permission
   */
  public void setProperty(final String property, final String value) throws AccumuloException, AccumuloSecurityException;
  
  /**
   * Removes a instance property from zookeeper
   * 
   * @param property
   *          the name of a per-table property
   * @throws AccumuloException
   *           if a general error occurs
   * @throws AccumuloSecurityException
   *           if the user does not have permission
   */
  public void removeProperty(final String property) throws AccumuloException, AccumuloSecurityException;
  
  public Map<String,String> getSystemConfiguration() throws AccumuloException, AccumuloSecurityException;
  
  public Map<String,String> getSiteConfiguration() throws AccumuloException, AccumuloSecurityException;
  
  /**
   * List the currently active tablet servers participating in the accumulo instance
   * 
   * @return A list of currently active tablet servers.
   */
  
  public List<String> getTabletServers();
  
  /**
   * List the active scans on tablet server.
   * 
   * @param tserver
   *          The tablet server address should be of the form <ip address>:<port>
   * @return A list of active scans on tablet server.
   * @throws AccumuloException
   * @throws AccumuloSecurityException
   */
  
  public List<ActiveScan> getActiveScans(String tserver) throws AccumuloException, AccumuloSecurityException;
  
  /**
   * List the active compaction running on a tablet server
   * 
   * @param tserver
   *          The tablet server address should be of the form <ip address>:<port>
   * @return the list of active compactions
   * @throws AccumuloException
   * @throws AccumuloSecurityException
   * @since 1.5.0
   */
  
  public List<ActiveCompaction> getActiveCompactions(String tserver) throws AccumuloException, AccumuloSecurityException;
  
  /**
   * Throws an exception if a tablet server can not be contacted.
   * 
   * @param tserver
   *          The tablet server address should be of the form <ip address>:<port>
   * @throws AccumuloException
   * @since 1.5.0
   */
  public void ping(String tserver) throws AccumuloException;
  
  /**
   * Test to see if the instance can load the given class as the given type. This check does not consider per table classpaths, see
   * {@link TableOperations#testClassLoad(String, String, String)}
   * 
   * @param className
   * @param asTypeName
   * @return true if the instance can load the given class as the given type, false otherwise
   * @throws AccumuloException
   */
  public boolean testClassLoad(final String className, final String asTypeName) throws AccumuloException, AccumuloSecurityException;
  
}
