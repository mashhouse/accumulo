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
package org.apache.accumulo.server.security;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.accumulo.core.Constants;
import org.apache.accumulo.core.client.AccumuloSecurityException;
import org.apache.accumulo.core.client.TableNotFoundException;
import org.apache.accumulo.core.client.impl.Tables;
import org.apache.accumulo.core.client.impl.Translator;
import org.apache.accumulo.core.client.impl.thrift.ThriftSecurityException;
import org.apache.accumulo.core.data.Column;
import org.apache.accumulo.core.data.KeyExtent;
import org.apache.accumulo.core.data.Range;
import org.apache.accumulo.core.data.thrift.IterInfo;
import org.apache.accumulo.core.data.thrift.TColumn;
import org.apache.accumulo.core.data.thrift.TKeyExtent;
import org.apache.accumulo.core.data.thrift.TRange;
import org.apache.accumulo.core.security.AuditLevel;
import org.apache.accumulo.core.security.Authorizations;
import org.apache.accumulo.core.security.SystemPermission;
import org.apache.accumulo.core.security.TablePermission;
import org.apache.accumulo.core.security.thrift.TCredentials;
import org.apache.accumulo.core.util.ByteBufferUtil;
import org.apache.accumulo.server.client.HdfsZooInstance;
import org.apache.accumulo.server.security.handler.Authenticator;
import org.apache.accumulo.server.security.handler.Authorizor;
import org.apache.accumulo.server.security.handler.PermissionHandler;
import org.apache.hadoop.io.Text;
import org.apache.log4j.Logger;

/**
 * 
 */
public class AuditedSecurityOperation extends SecurityOperation {
  
  public AuditedSecurityOperation(Authorizor author, Authenticator authent, PermissionHandler pm, String instanceId) {
    super(author, authent, pm, instanceId);
  }
  
  public static final Logger log = Logger.getLogger(AuditedSecurityOperation.class);
  
  public static synchronized SecurityOperation getInstance() {
    String instanceId = HdfsZooInstance.getInstance().getInstanceID();
    return getInstance(instanceId, false);
  }
  
  public static synchronized SecurityOperation getInstance(String instanceId, boolean initialize) {
    if (instance == null) {
      instance = new AuditedSecurityOperation(getAuthorizor(instanceId, initialize), getAuthenticator(instanceId, initialize), getPermHandler(instanceId,
          initialize), instanceId);
    }
    return instance;
  }

  private static String getTableName(String tableId) {
    try {
      return Tables.getTableName(HdfsZooInstance.getInstance(), tableId);
    } catch (TableNotFoundException e) {
      return "Unknown Table with ID " + tableId;
    }
  }
  
  private static StringBuilder getAuthString(List<ByteBuffer> authorizations) {
    StringBuilder auths = new StringBuilder();
    for (ByteBuffer bb : authorizations) {
      auths.append(ByteBufferUtil.toString(bb) + ",");
    }
    return auths;
  }
  
  private static boolean shouldAudit(TCredentials credentials, String tableId) {
    return !tableId.equals(Constants.METADATA_TABLE_ID) && shouldAudit(credentials);
  }
  
  private static boolean shouldAudit(TCredentials credentials) {
    return log.isEnabledFor(AuditLevel.AUDIT) && !credentials.getPrincipal().equals(SecurityConstants.SYSTEM_PRINCIPAL);
  }
  
  private void logError(TCredentials credentials, ThriftSecurityException ex, String template, Object... args) {
    log.warn("Error: authenticated operation failed: " + credentials.getPrincipal() + ": " + String.format(template, args), ex);
  }
  
  private void audit(TCredentials credentials, String template, Object... args) {
    if (shouldAudit(credentials)) {
      log.log(AuditLevel.AUDIT, "Using credentials " + credentials.getPrincipal() + ": " + String.format(template, args));
    }
  }
  
  private void audit(TCredentials credentials, boolean opSuccess, String template, Object... args) {
    if (shouldAudit(credentials)) {
      String prefix = opSuccess ? "Successful" : "Failed";
      log.log(AuditLevel.AUDIT, prefix + " operation using credentials " + credentials.getPrincipal() + ": " + String.format(template, args));
    }
  }
  
  @Override
  public Authorizations getUserAuthorizations(TCredentials credentials, String user) throws ThriftSecurityException {
    try {
      Authorizations result = super.getUserAuthorizations(credentials, user);
      audit(credentials, "got authorizations for %s", user);
      return result;
    } catch (ThriftSecurityException ex) {
      logError(credentials, ex, "getting authorizations for %s", user);
      throw ex;
    }
  }
  
  @Override
  public Authorizations getUserAuthorizations(TCredentials credentials) throws ThriftSecurityException {
    try {
      return getUserAuthorizations(credentials, credentials.getPrincipal());
    } catch (ThriftSecurityException ex) {
      throw ex;
    }
  }
  
  @Override
  public boolean canScan(TCredentials credentials, String tableId, TRange range, List<TColumn> columns, List<IterInfo> ssiList, Map<String,Map<String,String>> ssio, List<ByteBuffer> authorizations) throws ThriftSecurityException {
    if (shouldAudit(credentials, tableId)) {
      Range convertedRange = new Range(range);
      List<Column> convertedColumns = Translator.translate(columns, new Translator.TColumnTranslator());
      String tableName = getTableName(tableId);
      
      try {
        boolean canScan = super.canScan(credentials, tableId);
        audit(credentials, canScan, "checked scan with auths %s on table %s[%s] with range %s and columns %s, and an iterator list %s with options %s ", getAuthString(authorizations), tableName, tableId, convertedRange, convertedColumns, ssiList, ssio);
        
        return canScan;
      } catch (ThriftSecurityException ex) {
        logError(credentials, ex, "checking scan with auths %s on table %s[%s] with range %s and columns %s, and an iterator list %s with options %s ", getAuthString(authorizations), tableName, tableId, convertedRange, convertedColumns, ssiList, ssio);
        throw ex;
      }
    } else {
      return super.canScan(credentials, tableId);
    }
  }
  
  @Override
  public boolean canScan(TCredentials credentials, String tableId, Map<TKeyExtent,List<TRange>> tbatch, List<TColumn> tcolumns, List<IterInfo> ssiList, Map<String,Map<String,String>> ssio, List<ByteBuffer> authorizations) throws ThriftSecurityException {
    if (shouldAudit(credentials, tableId)) {
      @SuppressWarnings({"unchecked", "rawtypes"})
      Map<KeyExtent, List<Range>> convertedBatch = Translator.translate(tbatch, new Translator.TKeyExtentTranslator(), new Translator.ListTranslator(new Translator.TRangeTranslator()));
      List<Column> convertedColumns = Translator.translate(tcolumns, new Translator.TColumnTranslator());
      String tableName = getTableName(tableId);

      try {
        boolean canScan = super.canScan(credentials, tableId);
        audit(credentials, canScan, "checked scan with auths %s on table %s[%s] with range %s and columns %s, and an iterator list %s with options %s ", getAuthString(authorizations), tableName, tableId, convertedBatch, convertedColumns, ssiList, ssio);
        
        return canScan;
      } catch (ThriftSecurityException ex) {
        logError(credentials, ex, "checking scan with auths %s on table %s[%s] with range %s and columns %s, and an iterator list %s with options %s ", getAuthString(authorizations), tableName, tableId, convertedBatch, convertedColumns, ssiList, ssio);
        throw ex;
      }
    } else {
      return super.canScan(credentials, tableId);
    }
  }


  
  @Override
  public void changeAuthorizations(TCredentials credentials, String user, Authorizations authorizations) throws ThriftSecurityException {
    try {
      super.changeAuthorizations(credentials, user, authorizations);
      audit(credentials, "changed authorizations for %s to %s", user, authorizations);
    } catch (ThriftSecurityException ex) {
      logError(credentials, ex, "changing authorizations for %s to %s", user, authorizations);
      throw ex;
    }
  }
  
  @Override
  public void changePassword(TCredentials credentials, TCredentials newInfo) throws ThriftSecurityException {
    try {
      super.changePassword(credentials, newInfo);
      audit(credentials, "changed password for %s", newInfo.getPrincipal());
    } catch (ThriftSecurityException ex) {
      logError(credentials, ex, "changing password for %s", newInfo.getPrincipal());
      throw ex;
    }
  }
  
  @Override
  public void createUser(TCredentials credentials, TCredentials newUser, Authorizations authorizations) throws ThriftSecurityException {
    try {
      super.createUser(credentials, newUser, authorizations);
      audit(credentials, "created user %s with %s", newUser.getPrincipal(), authorizations);
    } catch (ThriftSecurityException ex) {
      logError(credentials, ex, "creating user %s with %s", newUser.getPrincipal(), authorizations);
      throw ex;
    }
  }
  
  @Override
  public boolean canCreateTable(TCredentials c, String tableName) throws ThriftSecurityException {
    try {
      boolean result = super.canCreateTable(c);
      audit(c, result, "checked can create table %s", tableName);
      return result;
    } catch (ThriftSecurityException ex) {
      logError(c, ex, "checking can create table %s", tableName);
      throw ex;
    }
  }
  
  @Override
  public boolean canDeleteTable(TCredentials c, String tableId) throws ThriftSecurityException {
    String tableName = getTableName(tableId);
    
    try {
      boolean result = super.canDeleteTable(c, tableId);
      audit(c, result, "checked can delete table %s[%s]", tableName, tableId);
      return result;
    } catch (ThriftSecurityException ex) {
      logError(c, ex, "checking can create table %s[%s]", tableName, tableId);
      throw ex;
    }
  }
  
  @Override
  public boolean canRenameTable(TCredentials c, String tableId, String oldTableName, String newTableName) throws ThriftSecurityException {
    try {
      boolean result = super.canRenameTable(c, tableId, oldTableName, newTableName);
      audit(c, result, "checked can rename table %s[%s] to %s", oldTableName, tableId, newTableName);
      return result;
    } catch (ThriftSecurityException ex) {
      logError(c, ex, "checking can rename table %s[%s] to %s", oldTableName, tableId, newTableName);
      throw ex;
    }
  }
  
  @Override
  public boolean canCloneTable(TCredentials c, String tableId, String tableName) throws ThriftSecurityException {
    String oldTableName = getTableName(tableId);
    
    try {
      boolean result = super.canCloneTable(c, tableId, tableName);
      audit(c, result, "checked can clone table %s[%s] to table %s", oldTableName, tableId, tableName);
      return result;
    } catch (ThriftSecurityException ex) {
      logError(c, ex, "checking can clone table %s[%s] to table %s", oldTableName, tableId, tableName);
      throw ex;
    }
  }
  
  @Override
  public boolean canDeleteRange(TCredentials c, String tableId, String tableName, Text startRow, Text endRow) throws ThriftSecurityException {
    try {
      boolean result = super.canDeleteRange(c, tableId, tableName, startRow, endRow);
      audit(c, result, "checked can delete range in table %s[%s] from start %s to end %s", tableName, tableId, startRow.toString(), endRow.toString());
      return result;
    } catch (ThriftSecurityException ex) {
      logError(c, ex, "checking can delete range in table %s[%s] from start %s to end %s", tableName, tableId, startRow.toString(), endRow.toString());
      throw ex;
    }
  }
  
  @Override
  public boolean canBulkImport(TCredentials c, String tableId, String tableName, String dir, String failDir) throws ThriftSecurityException {
    try {
      boolean result = super.canBulkImport(c, tableId);
      audit(c, result, "checked can bulk import into table %s[%s] from dir %s and fail dir %s", tableName, tableId, dir, failDir);
      return result;
    } catch (ThriftSecurityException ex) {
      logError(c, ex, "checking can bulk import into table %s[%s] from dir %s and fail dir %s", tableName, tableId, dir, failDir);
      throw ex;
    }
  }
  
  @Override
  public boolean canImport(TCredentials credentials, String tableName, String importDir) throws ThriftSecurityException {
    try {
      boolean result = super.canImport(credentials, tableName, importDir);
      audit(credentials, result, "checked can import into table %s from dir %s", tableName, importDir);
      return result;
    } catch (ThriftSecurityException ex) {
      logError(credentials, ex, "checking can import into table %s from dir %s", tableName, importDir);
      throw ex;
    }
  }
  
  @Override
  public boolean canExport(TCredentials credentials, String tableId, String tableName, String exportDir) throws ThriftSecurityException {
    try {
      boolean result = super.canExport(credentials, tableId, tableName, exportDir);
      audit(credentials, result, "checked can export from table %s[%s] into dir %s", tableName, tableId, exportDir);
      return result;
    } catch (ThriftSecurityException ex) {
      logError(credentials, ex, "checking can export from table %s[%s] into dir %s", tableName, tableId, exportDir);
      throw ex;
    }
  }
  
  @Override
  public void dropUser(TCredentials credentials, String user) throws ThriftSecurityException {
    try {
      super.dropUser(credentials, user);
      audit(credentials, "dropped user %s", user);
    } catch (ThriftSecurityException ex) {
      logError(credentials, ex, "dropping user %s", user);
      throw ex;
    }
  }
  
  @Override
  public void grantSystemPermission(TCredentials credentials, String user, SystemPermission permission) throws ThriftSecurityException {
    try {
      super.grantSystemPermission(credentials, user, permission);
      audit(credentials, "granted system permission %s for %s", permission, user);
    } catch (ThriftSecurityException ex) {
      logError(credentials, ex, "granting system permission %s for %s", permission, user);
      throw ex;
    }
  }
  
  @Override
  public void grantTablePermission(TCredentials credentials, String user, String table, TablePermission permission) throws ThriftSecurityException {
    try {
      super.grantTablePermission(credentials, user, table, permission);
      audit(credentials, "granted table permission %s on table %s for %s", permission, table, user);
    } catch (ThriftSecurityException ex) {
      logError(credentials, ex, "granting table permission %s on table %s for %s", permission, table, user);
      throw ex;
    }
  }
  
  @Override
  public void revokeSystemPermission(TCredentials credentials, String user, SystemPermission permission) throws ThriftSecurityException {
    try {
      super.revokeSystemPermission(credentials, user, permission);
      audit(credentials, "revoked system permission %s for %s", permission, user);
    } catch (ThriftSecurityException ex) {
      logError(credentials, ex, "revoking system permission %s for %s", permission, user);
      throw ex;
    }
  }
  
  @Override
  public void revokeTablePermission(TCredentials credentials, String user, String table, TablePermission permission) throws ThriftSecurityException {
    try {
      super.revokeTablePermission(credentials, user, table, permission);
      audit(credentials, "revoked table permission %s on table %s for %s", permission, table, user);
    } catch (ThriftSecurityException ex) {
      logError(credentials, ex, "revoking table permission %s on table %s for %s", permission, table, user);
      throw ex;
    }
  }
  
  @Override
  public boolean hasSystemPermission(TCredentials credentials, String user, SystemPermission permission) throws ThriftSecurityException {
    try {
      boolean result = super.hasSystemPermission(credentials, user, permission);
      audit(credentials, result, "checked system permission %s for %s", permission, user);
      return result;
    } catch (ThriftSecurityException ex) {
      logError(credentials, ex, "checking system permission %s for %s", permission, user);
      throw ex;
    }
  }
  
  @Override
  public boolean hasTablePermission(TCredentials credentials, String user, String table, TablePermission permission) throws ThriftSecurityException {
    try {
      boolean result = super.hasTablePermission(credentials, user, table, permission);
      audit(credentials, result, "checked table permission %s on table %s for %s", permission, table, user);
      return result;
    } catch (ThriftSecurityException ex) {
      logError(credentials, ex, "checking table permission %s on table %s for %s", permission, table, user);
      throw ex;
    }
  }
  
  @Override
  public Set<String> listUsers(TCredentials credentials) throws ThriftSecurityException {
    try {
      Set<String> result = super.listUsers(credentials);
      audit(credentials, "listed users");
      return result;
    } catch (ThriftSecurityException ex) {
      logError(credentials, ex, "listing users");
      throw ex;
    }
  }
  
  
  @Override
  public void initializeSecurity(TCredentials credentials, String principal, byte[] token) throws AccumuloSecurityException, ThriftSecurityException {
    super.initializeSecurity(credentials, principal, token);
    log.info("Initialized root user with username: " + principal + " at the request of user " + credentials.getPrincipal());
  }
}
