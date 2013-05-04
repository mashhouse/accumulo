package org.apache.accumulo.test;

import org.apache.accumulo.core.Constants;
import org.apache.accumulo.core.client.*;
import org.apache.accumulo.core.client.security.tokens.PasswordToken;
import org.apache.accumulo.core.data.Key;
import org.apache.accumulo.core.data.Mutation;
import org.apache.accumulo.core.data.Range;
import org.apache.accumulo.core.data.Value;
import org.apache.accumulo.core.security.Authorizations;
import org.apache.accumulo.core.security.SystemPermission;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.LineIterator;
import org.apache.hadoop.io.Text;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;

import static org.junit.Assert.assertEquals;

/**
 * Tests that Accumulo is outputting audit messages as expected. Since this is using MiniAccumuloCluster, it could take a while if we test everything in isolation.
 * We test blocks of related operations, run the whole test in one MiniAccumulo instance, trying to clean up objects between each test.
 * The MiniAccumuloClusterTest sets up the log4j stuff differently to an installed instance, instead piping everything through stdout and writing to a set location
 * so we have to find the logs and grep the bits we need out.
 */
public class AuditMessageTest {


  private static final String AUDIT_USER_1 = "AuditUser1";
  private static final String AUDIT_USER_2 = "AuditUser2";
  private static final PasswordToken PASSWORD_TOKEN = new PasswordToken("password");
  private static final String OLD_TEST_TABLE_NAME = "apples";
  private static final String NEW_TEST_TABLE_NAME = "oranges";
  private static TemporaryFolder folder = new TemporaryFolder();
  private static MiniAccumuloCluster accumulo;
  private Connector auditConnector;
  private Connector conn;
  private static String lastAuditTimestamp;

  /**
   * Returns a List of Audit messages that have been grep'd out of the MiniAccumuloCluster output.
   * 
   * @param logDir
   *          The directory the logfiles are found
   * @param startTimestamp
   *          Only return messages that occur after the startTimestamp. Can be null.
   * @return A List of the Audit messages, sorted (so in chronological order).
   */
  private static ArrayList<String> getAuditMessages(File logDir, String startTimestamp) throws IOException {
    ArrayList<String> result = new ArrayList<String>();
    for (File file : logDir.listFiles()) {
      if (file.isFile() && file.canRead()) {
        LineIterator it = FileUtils.lineIterator(file, "UTF-8");
        try {
          while (it.hasNext()) {
            String line = it.nextLine();
            if (line.matches(".* \\[" + Constants.AUDITLOG + "\\s*\\].*")) {
              // Only include the message if startTimestamp is null. or the message occurred after the startTimestamp value
              if ((startTimestamp == null) || (startTimestamp != null && line.substring(0, 23).compareTo(startTimestamp) > 0))
                result.add(line);
            }
          }
        } finally {
          LineIterator.closeQuietly(it);
        }
      }
    }
    java.util.Collections.sort(result);
    return result;
  }


  private static ArrayList<String> findAuditMessage(ArrayList<String> input, String pattern) {
    ArrayList<String> result = new ArrayList<String>();
    for (String s : input) {
      if (s.matches(pattern))
        result.add(s);
    }
    return result;
  }

  @BeforeClass
  public static void setupMiniCluster() throws Exception {
    folder.create();
    Logger.getLogger("org.apache.zookeeper").setLevel(Level.ERROR);

    accumulo = new MiniAccumuloCluster(folder.getRoot(), "superSecret");
    accumulo.start();
  }

  @Before
  public void setup() throws AccumuloException, AccumuloSecurityException {
    conn = new ZooKeeperInstance(accumulo.getInstanceName(), accumulo.getZooKeepers()).getConnector("root", new PasswordToken("superSecret"));

    // I don't want to recreate the instance for every test since it will take ages.
    // If we run every test as non-root users, I can drop these users every test which should effectively
    // reset the environment.

    if (conn.securityOperations().listLocalUsers().contains(AUDIT_USER_1))
      conn.securityOperations().dropLocalUser(AUDIT_USER_1);
    if (conn.securityOperations().listLocalUsers().contains(AUDIT_USER_2))
      conn.securityOperations().dropLocalUser(AUDIT_USER_2);
  }

  @SuppressWarnings("unchecked")
  @Test
  public void testAudit() throws AccumuloException, AccumuloSecurityException, TableExistsException, TableNotFoundException, IOException {
    
    File logDir = accumulo.getLogDir();
    
    Authorizations auths = new Authorizations("private", "public");
    conn.securityOperations().changeUserAuthorizations("root", auths);
    conn.tableOperations().create(OLD_TEST_TABLE_NAME);
    conn.tableOperations().rename(OLD_TEST_TABLE_NAME, NEW_TEST_TABLE_NAME);
    BatchWriter bw = conn.createBatchWriter(NEW_TEST_TABLE_NAME, new BatchWriterConfig());
    Mutation m = new Mutation("r1");
    m.put("cf1", "cq1", "v1");
    m.put("cf1", "cq2", "v3");
    bw.addMutation(m);
    bw.close();
    conn.tableOperations().clone(NEW_TEST_TABLE_NAME, OLD_TEST_TABLE_NAME, true, Collections.EMPTY_MAP, Collections.EMPTY_SET);
    conn.tableOperations().delete(OLD_TEST_TABLE_NAME);
    Scanner scanner = conn.createScanner(NEW_TEST_TABLE_NAME, auths);
    for (Map.Entry<Key,Value> entry : scanner) {
      System.out.println("Scanner row: " + entry.getKey() + " " + entry.getValue());
    }
    BatchScanner bs = conn.createBatchScanner(NEW_TEST_TABLE_NAME, auths, 1);
    bs.fetchColumn(new Text("cf1"), new Text("cq1"));
    bs.setRanges(Arrays.asList(new Range("r1", "r~")));
    
    for (Map.Entry<Key,Value> entry : bs) {
      System.out.println("BatchScanner row: " + entry.getKey() + " " + entry.getValue());
    }
    
    conn.tableOperations().deleteRows(NEW_TEST_TABLE_NAME, new Text("r1"), new Text("r~"));
    
    // When testing bulk import dir must be empty
    // conn.tableOperations().importDirectory(NEW_TEST_TABLE_NAME, "/tmp/jkthen1", "/tmp/jkthen2", true);
    
    conn.tableOperations().offline(NEW_TEST_TABLE_NAME);
    conn.tableOperations().delete(NEW_TEST_TABLE_NAME);
    
    System.out.println("Start of captured audit messages");
    ArrayList<String> auditMessages = getAuditMessages(logDir, null);
    for (String s : auditMessages) {
      System.out.println(s);
    }
    System.out.println("End of captured audit messages");
    lastAuditTimestamp = (auditMessages.get(auditMessages.size() - 1)).substring(0, 23);
  }

  @Test
  public void testTableOperationsAudits() throws AccumuloException, AccumuloSecurityException, TableExistsException, TableNotFoundException, IOException {

    File logDir = accumulo.getLogDir();

    conn.securityOperations().createLocalUser(AUDIT_USER_1, PASSWORD_TOKEN);
    conn.securityOperations().grantSystemPermission(AUDIT_USER_1, SystemPermission.SYSTEM);
    conn.securityOperations().grantSystemPermission(AUDIT_USER_1, SystemPermission.CREATE_TABLE);

    // Connect as Audit User and do a bunch of stuff.
    auditConnector = new ZooKeeperInstance(accumulo.getInstanceName(), accumulo.getZooKeepers()).getConnector(AUDIT_USER_1, PASSWORD_TOKEN);
    auditConnector.tableOperations().create(OLD_TEST_TABLE_NAME);
    auditConnector.tableOperations().rename(OLD_TEST_TABLE_NAME, NEW_TEST_TABLE_NAME);
    auditConnector.tableOperations().clone(NEW_TEST_TABLE_NAME, OLD_TEST_TABLE_NAME, true, Collections.EMPTY_MAP, Collections.EMPTY_SET);
    auditConnector.tableOperations().delete(OLD_TEST_TABLE_NAME);
    auditConnector.tableOperations().offline(NEW_TEST_TABLE_NAME);
    auditConnector.tableOperations().delete(NEW_TEST_TABLE_NAME);

    // Grab the audit messages
    System.out.println("Start of captured audit messages");
    ArrayList<String> auditMessages = getAuditMessages(logDir, lastAuditTimestamp);
    for (String s : auditMessages) {
      System.out.println(s);
    }
    System.out.println("End of captured audit messages");
    lastAuditTimestamp = (auditMessages.get(auditMessages.size() - 1)).substring(0, 23);

    assertEquals(1, findAuditMessage(auditMessages, ".*action: createTable; targetTable: " + OLD_TEST_TABLE_NAME + ".*").size());
    assertEquals(1, findAuditMessage(auditMessages, ".*action: renameTable; targetTable: " + OLD_TEST_TABLE_NAME + ".*").size());
    assertEquals(1, findAuditMessage(auditMessages, ".*action: cloneTable; targetTable: " + NEW_TEST_TABLE_NAME + ".*").size());
    assertEquals(1, findAuditMessage(auditMessages, ".*action: deleteTable; targetTable: " + OLD_TEST_TABLE_NAME + ".*").size());
    assertEquals(1, findAuditMessage(auditMessages, ".*action: offlineTable; targetTable: " + NEW_TEST_TABLE_NAME + ".*").size());
    assertEquals(1, findAuditMessage(auditMessages, ".*action: deleteTable; targetTable: " + NEW_TEST_TABLE_NAME + ".*").size());

  }
}
