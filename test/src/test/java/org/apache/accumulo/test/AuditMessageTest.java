package org.apache.accumulo.test;

import java.io.File;
import java.io.IOException;
import java.util.*;

import org.apache.accumulo.core.Constants;
import org.apache.accumulo.core.client.*;
import org.apache.accumulo.core.client.Scanner;
import org.apache.accumulo.core.data.Key;
import org.apache.accumulo.core.data.Mutation;
import org.apache.accumulo.core.data.Range;
import org.apache.accumulo.core.data.Value;
import org.apache.accumulo.core.security.Authorizations;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.LineIterator;
import org.apache.hadoop.io.Text;
import org.junit.Test;

public class AuditMessageTest extends MiniAccumuloClusterTest {
  
  /**
   * Returns a List of Audit messages that have been grep'd out of the MiniAccumuloCluster output.
   * 
   * @param logDir
   *          The directory the logfiles are found
   * @return A List of the Audit messages, sorted by timestamp.
   */
  private ArrayList<String> getAuditMessages(File logDir) throws IOException {
    ArrayList<String> result = new ArrayList<String>();
    for (File file : logDir.listFiles()) {
      if (file.isFile() && file.canRead()) {
        LineIterator it = FileUtils.lineIterator(file, "UTF-8");
        try {
          while (it.hasNext()) {
            String line = it.nextLine();
            if (line.matches(".* \\[" + Constants.AUDITLOG + "\\].*")) {
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
    List<String> auditMessages = getAuditMessages(logDir);
    for (String s : auditMessages) {
      System.out.println(s);
    }
    System.out.println("End of captured audit messages");
  }
}
