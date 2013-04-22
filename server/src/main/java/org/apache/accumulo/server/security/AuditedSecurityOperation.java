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
  public static final Logger audit = Logger.getLogger("Audit");

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


  /*
    Three auditing methods try to capture the 4 states we might have here.
    logError is in response to a thrown exception, the operation failed (perhaps due to insufficient privs, or some other reason)
    audit(credentials, template, args) is a successful operation
    audit(credentials, permitted, template, args) is a privileges check that is either permitted or denied. We don't know
        if the operation went on to be successful or not at this point, we would have to go digging through loads of other code to find it.
     */
  private void logError(TCredentials credentials, ThriftSecurityException ex, String template, Object... args) {
    log.warn("operation: failed; user: " + credentials.getPrincipal() + "; " + String.format(template, args), ex);
  }
  
  private void audit(TCredentials credentials, String template, Object... args) {
    if (shouldAudit(credentials)) {
      audit.info("operation: success; user: " + credentials.getPrincipal() + ": " + String.format(template, args));
    }
  }

  private void audit(TCredentials credentials, boolean permitted, String template, Object... args) {
    if (shouldAudit(credentials)) {
      String prefix = permitted ? "permitted" : "denied";
      audit.info("operation: " + prefix + "; user: " + credentials.getPrincipal() + "; " + String.format(template, args));
    }
  }



  @Override
  public boolean canScan(TCredentials credentials, String tableId, TRange range, List<TColumn> columns, List<IterInfo> ssiList, Map<String,Map<String,String>> ssio, List<ByteBuffer> authorizations) throws ThriftSecurityException {
    if (shouldAudit(credentials, tableId)) {
      Range convertedRange = new Range(range);
      List<Column> convertedColumns = Translator.translate(columns, new Translator.TColumnTranslator());
      String tableName = getTableName(tableId);

      String auditTemplate = "action: scan; targetTable: %s; targetTableID: %s; authorizations: %s; range: %s; columns: %s; iterators: %s; iteratorOptions: %s;";
      
      try {
        boolean canScan = super.canScan(credentials, tableId);
        audit(credentials, canScan, auditTemplate,  tableName, tableId, getAuthString(authorizations), convertedRange, convertedColumns, ssiList, ssio);
        
        return canScan;
      } catch (ThriftSecurityException ex) {
        logError(credentials, ex, auditTemplate, getAuthString(authorizations), tableName, tableId, convertedRange, convertedColumns, ssiList, ssio);
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
      String auditTemplate = "action: scan; targetTable: %s; targetTableID: %s; authorizations: %s; range: %s; columns: %s; iterators: %s; iteratorOptions: %s;";


        try {
        boolean canScan = super.canScan(credentials, tableId);
        audit(credentials, canScan, auditTemplate, tableName, tableId, getAuthString(authorizations), convertedBatch, convertedColumns, ssiList, ssio);
        
        return canScan;
      } catch (ThriftSecurityException ex) {
        logError(credentials, ex, auditTemplate, getAuthString(authorizations), tableName, tableId, convertedBatch, convertedColumns, ssiList, ssio);
        throw ex;
      }
    } else {
      return super.canScan(credentials, tableId);
    }
  }


  
  @Override
  public void changeAuthorizations(TCredentials credentials, String user, Authorizations authorizations) throws ThriftSecurityException {
      String auditTemplate = "action: change authorizations; targetUser: %s; authorizations: %s";
      try {
      super.changeAuthorizations(credentials, user, authorizations);
      audit(credentials, auditTemplate, user, authorizations);
    } catch (ThriftSecurityException ex) {
      logError(credentials, ex, auditTemplate, user, authorizations);
      throw ex;
    }
  }
  
  @Override
  public void changePassword(TCredentials credentials, TCredentials newInfo) throws ThriftSecurityException {
      String auditTemplate = "action: changePassword; targetUser: %s;";
      try {
      super.changePassword(credentials, newInfo);
      audit(credentials, auditTemplate, newInfo.getPrincipal());
    } catch (ThriftSecurityException ex) {
      logError(credentials, ex, auditTemplate, newInfo.getPrincipal());
      throw ex;
    }
  }
  
  @Override
  public void createUser(TCredentials credentials, TCredentials newUser, Authorizations authorizations) throws ThriftSecurityException {
      String auditTemplate = "action: createUser; targetUser: %s; Authorizations: %s;";
      try {
      super.createUser(credentials, newUser, authorizations);
      audit(credentials, auditTemplate, newUser.getPrincipal(), authorizations);
    } catch (ThriftSecurityException ex) {
      logError(credentials, ex, auditTemplate, newUser.getPrincipal(), authorizations);
      throw ex;
    }
  }
  
  @Override
  public boolean canCreateTable(TCredentials c, String tableName) throws ThriftSecurityException {
      String auditTemplate = "action: createTable; targetTable: %s;";
      try {
      boolean result = super.canCreateTable(c);
      audit(c, result, auditTemplate, tableName);
      return result;
    } catch (ThriftSecurityException ex) {
      logError(c, ex, auditTemplate, tableName);
      throw ex;
    }
  }
  
  @Override
  public boolean canDeleteTable(TCredentials c, String tableId) throws ThriftSecurityException {
    String tableName = getTableName(tableId);
    String auditTemplate = "action: deleteTable; targetTable: %s; TargetTableID: %s;";
    try {
      boolean result = super.canDeleteTable(c, tableId);
      audit(c, result, auditTemplate, tableName, tableId);
      return result;
    } catch (ThriftSecurityException ex) {
      logError(c, ex, auditTemplate, tableName, tableId);
      throw ex;
    }
  }
  
  @Override
  public boolean canRenameTable(TCredentials c, String tableId, String oldTableName, String newTableName) throws ThriftSecurityException {
      String auditTemplate = "action: renameTable; targetTable: %s; targetTableID: %s; newTableName: %s;";
      try {
      boolean result = super.canRenameTable(c, tableId, oldTableName, newTableName);
      audit(c, result, auditTemplate, oldTableName, tableId, newTableName);
      return result;
    } catch (ThriftSecurityException ex) {
      logError(c, ex, auditTemplate, oldTableName, tableId, newTableName);
      throw ex;
    }
  }
  
  @Override
  public boolean canCloneTable(TCredentials c, String tableId, String tableName) throws ThriftSecurityException {
    String oldTableName = getTableName(tableId);
    String auditTemplate = "action: cloneTable; targetTable: %s; targetTableID: %s; newTableName: %s";
    try {
      boolean result = super.canCloneTable(c, tableId, tableName);
      audit(c, result, auditTemplate, oldTableName, tableId, tableName);
      return result;
    } catch (ThriftSecurityException ex) {
      logError(c, ex, auditTemplate, oldTableName, tableId, tableName);
      throw ex;
    }
  }
  
  @Override
  public boolean canDeleteRange(TCredentials c, String tableId, String tableName, Text startRow, Text endRow) throws ThriftSecurityException {
      String auditTemplate = "action: deleteData; targetTab;e: %s; targetTableID: %s; range: %s-%s;";
      try {
      boolean result = super.canDeleteRange(c, tableId, tableName, startRow, endRow);
      audit(c, result, auditTemplate, tableName, tableId, startRow.toString(), endRow.toString());
      return result;
    } catch (ThriftSecurityException ex) {
      logError(c, ex, auditTemplate, tableName, tableId, startRow.toString(), endRow.toString());
      throw ex;
    }
  }
  
  @Override
  public boolean canBulkImport(TCredentials c, String tableId, String tableName, String dir, String failDir) throws ThriftSecurityException {
      String auditTemplate = "action: bulkImport; targetTable: %s; targetTableID: %s; dataDir: %s; failDir: %s;";
      try {
      boolean result = super.canBulkImport(c, tableId);
      audit(c, result, auditTemplate, tableName, tableId, dir, failDir);
      return result;
    } catch (ThriftSecurityException ex) {
      logError(c, ex, auditTemplate, tableName, tableId, dir, failDir);
      throw ex;
    }
  }
  
  @Override
  public boolean canImport(TCredentials credentials, String tableName, String importDir) throws ThriftSecurityException {
      String auditTemplate = "action: import; targetTable: %s; dataDir: %s;";

      try {
      boolean result = super.canImport(credentials, tableName, importDir);
      audit(credentials, result, auditTemplate, tableName, importDir);
      return result;
    } catch (ThriftSecurityException ex) {
      logError(credentials, ex, auditTemplate, tableName, importDir);
      throw ex;
    }
  }
  
  @Override
  public boolean canExport(TCredentials credentials, String tableId, String tableName, String exportDir) throws ThriftSecurityException {
      String auditTemplate = "action: export; targetTable: %s; targetTableID: %s; dataDir: %s;";

      try {
      boolean result = super.canExport(credentials, tableId, tableName, exportDir);
      audit(credentials, result, auditTemplate, tableName, tableId, exportDir);
      return result;
    } catch (ThriftSecurityException ex) {
      logError(credentials, ex, auditTemplate, tableName, tableId, exportDir);
      throw ex;
    }
  }
  
  @Override
  public void dropUser(TCredentials credentials, String user) throws ThriftSecurityException {
      String auditTemplate = "action: dropUser; targetUser: %s;";
      try {
      super.dropUser(credentials, user);
      audit(credentials, auditTemplate, user);
    } catch (ThriftSecurityException ex) {
      logError(credentials, ex, auditTemplate, user);
      throw ex;
    }
  }
  
  @Override
  public void grantSystemPermission(TCredentials credentials, String user, SystemPermission permission) throws ThriftSecurityException {
      String auditTemplate = "action: grantSystemPermission; permission:%s; targetUser: %s;";
      try {
      super.grantSystemPermission(credentials, user, permission);
      audit(credentials, auditTemplate, permission, user);
    } catch (ThriftSecurityException ex) {
      logError(credentials, ex, auditTemplate, permission, user);
      throw ex;
    }
  }
  
  @Override
  public void grantTablePermission(TCredentials credentials, String user, String table, TablePermission permission) throws ThriftSecurityException {
      String auditTemplate = "action: grantTablePermission; permission: %s; targetTable: %s; targetUser: %s;";

      try {
      super.grantTablePermission(credentials, user, table, permission);
      audit(credentials, auditTemplate, permission, table, user);
    } catch (ThriftSecurityException ex) {
      logError(credentials, ex, auditTemplate, permission, table, user);
      throw ex;
    }
  }
  
  @Override
  public void revokeSystemPermission(TCredentials credentials, String user, SystemPermission permission) throws ThriftSecurityException {
      String auditTemplate = "action: revokeSystemPermission; permission:%s; targetUser: %s;";

      try {
      super.revokeSystemPermission(credentials, user, permission);
      audit(credentials, auditTemplate, permission, user);
    } catch (ThriftSecurityException ex) {
      logError(credentials, ex, auditTemplate, permission, user);
      throw ex;
    }
  }
  
  @Override
  public void revokeTablePermission(TCredentials credentials, String user, String table, TablePermission permission) throws ThriftSecurityException {
      String auditTemplate = "action: revokeTablePermission; permission: %s; targetTable: %s; targetUser: %s;";

      try {
      super.revokeTablePermission(credentials, user, table, permission);
      audit(credentials, auditTemplate, permission, table, user);
    } catch (ThriftSecurityException ex) {
      logError(credentials, ex, auditTemplate, permission, table, user);
      throw ex;
    }
  }

  
  
  @Override
  public void initializeSecurity(TCredentials credentials, String principal, byte[] token) throws AccumuloSecurityException, ThriftSecurityException {
    super.initializeSecurity(credentials, principal, token);
    log.info("Initialized root user with username: " + principal + " at the request of user " + credentials.getPrincipal());
  }
}
