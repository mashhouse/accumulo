/**
 * Autogenerated by Thrift
 *
 * DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
 */
package org.apache.accumulo.core.data.thrift;

import org.apache.thrift.*;
import org.apache.thrift.meta_data.*;
import org.apache.thrift.protocol.*;

@SuppressWarnings("serial")
public class MapFileInfo implements TBase<MapFileInfo,MapFileInfo._Fields>, java.io.Serializable, Cloneable {
  private static final TStruct STRUCT_DESC = new TStruct("MapFileInfo");
  
  private static final TField ESTIMATED_SIZE_FIELD_DESC = new TField("estimatedSize", TType.I64, (short) 1);
  
  public long estimatedSize;
  
  /** The set of fields this struct contains, along with convenience methods for finding and manipulating them. */
  public enum _Fields implements TFieldIdEnum {
    ESTIMATED_SIZE((short) 1, "estimatedSize");
    
    private static final java.util.Map<String,_Fields> byName = new java.util.HashMap<String,_Fields>();
    
    static {
      for (_Fields field : java.util.EnumSet.allOf(_Fields.class)) {
        byName.put(field.getFieldName(), field);
      }
    }
    
    /**
     * Find the _Fields constant that matches fieldId, or null if its not found.
     */
    public static _Fields findByThriftId(int fieldId) {
      switch (fieldId) {
        case 1: // ESTIMATED_SIZE
          return ESTIMATED_SIZE;
        default:
          return null;
      }
    }
    
    /**
     * Find the _Fields constant that matches fieldId, throwing an exception if it is not found.
     */
    public static _Fields findByThriftIdOrThrow(int fieldId) {
      _Fields fields = findByThriftId(fieldId);
      if (fields == null)
        throw new IllegalArgumentException("Field " + fieldId + " doesn't exist!");
      return fields;
    }
    
    /**
     * Find the _Fields constant that matches name, or null if its not found.
     */
    public static _Fields findByName(String name) {
      return byName.get(name);
    }
    
    private final short _thriftId;
    private final String _fieldName;
    
    _Fields(short thriftId, String fieldName) {
      _thriftId = thriftId;
      _fieldName = fieldName;
    }
    
    public short getThriftFieldId() {
      return _thriftId;
    }
    
    public String getFieldName() {
      return _fieldName;
    }
  }
  
  // isset id assignments
  private static final int __ESTIMATEDSIZE_ISSET_ID = 0;
  private java.util.BitSet __isset_bit_vector = new java.util.BitSet(1);
  
  public static final java.util.Map<_Fields,FieldMetaData> metaDataMap;
  static {
    java.util.Map<_Fields,FieldMetaData> tmpMap = new java.util.EnumMap<_Fields,FieldMetaData>(_Fields.class);
    tmpMap.put(_Fields.ESTIMATED_SIZE, new FieldMetaData("estimatedSize", TFieldRequirementType.DEFAULT, new FieldValueMetaData(TType.I64)));
    metaDataMap = java.util.Collections.unmodifiableMap(tmpMap);
    FieldMetaData.addStructMetaDataMap(MapFileInfo.class, metaDataMap);
  }
  
  public MapFileInfo() {}
  
  public MapFileInfo(long estimatedSize) {
    this();
    this.estimatedSize = estimatedSize;
    setEstimatedSizeIsSet(true);
  }
  
  /**
   * Performs a deep copy on <i>other</i>.
   */
  public MapFileInfo(MapFileInfo other) {
    __isset_bit_vector.clear();
    __isset_bit_vector.or(other.__isset_bit_vector);
    this.estimatedSize = other.estimatedSize;
  }
  
  public MapFileInfo deepCopy() {
    return new MapFileInfo(this);
  }
  
  @Deprecated
  public MapFileInfo clone() {
    return new MapFileInfo(this);
  }
  
  public long getEstimatedSize() {
    return this.estimatedSize;
  }
  
  public MapFileInfo setEstimatedSize(long estimatedSize) {
    this.estimatedSize = estimatedSize;
    setEstimatedSizeIsSet(true);
    return this;
  }
  
  public void unsetEstimatedSize() {
    __isset_bit_vector.clear(__ESTIMATEDSIZE_ISSET_ID);
  }
  
  /** Returns true if field estimatedSize is set (has been asigned a value) and false otherwise */
  public boolean isSetEstimatedSize() {
    return __isset_bit_vector.get(__ESTIMATEDSIZE_ISSET_ID);
  }
  
  public void setEstimatedSizeIsSet(boolean value) {
    __isset_bit_vector.set(__ESTIMATEDSIZE_ISSET_ID, value);
  }
  
  public void setFieldValue(_Fields field, Object value) {
    switch (field) {
      case ESTIMATED_SIZE:
        if (value == null) {
          unsetEstimatedSize();
        } else {
          setEstimatedSize((Long) value);
        }
        break;
    
    }
  }
  
  public void setFieldValue(int fieldID, Object value) {
    setFieldValue(_Fields.findByThriftIdOrThrow(fieldID), value);
  }
  
  public Object getFieldValue(_Fields field) {
    switch (field) {
      case ESTIMATED_SIZE:
        return new Long(getEstimatedSize());
        
    }
    throw new IllegalStateException();
  }
  
  public Object getFieldValue(int fieldId) {
    return getFieldValue(_Fields.findByThriftIdOrThrow(fieldId));
  }
  
  /** Returns true if field corresponding to fieldID is set (has been asigned a value) and false otherwise */
  public boolean isSet(_Fields field) {
    switch (field) {
      case ESTIMATED_SIZE:
        return isSetEstimatedSize();
    }
    throw new IllegalStateException();
  }
  
  public boolean isSet(int fieldID) {
    return isSet(_Fields.findByThriftIdOrThrow(fieldID));
  }
  
  @Override
  public boolean equals(Object that) {
    if (that == null)
      return false;
    if (that instanceof MapFileInfo)
      return this.equals((MapFileInfo) that);
    return false;
  }
  
  public boolean equals(MapFileInfo that) {
    if (that == null)
      return false;
    
    boolean this_present_estimatedSize = true;
    boolean that_present_estimatedSize = true;
    if (this_present_estimatedSize || that_present_estimatedSize) {
      if (!(this_present_estimatedSize && that_present_estimatedSize))
        return false;
      if (this.estimatedSize != that.estimatedSize)
        return false;
    }
    
    return true;
  }
  
  @Override
  public int hashCode() {
    return 0;
  }
  
  public int compareTo(MapFileInfo other) {
    if (!getClass().equals(other.getClass())) {
      return getClass().getName().compareTo(other.getClass().getName());
    }
    
    int lastComparison = 0;
    MapFileInfo typedOther = (MapFileInfo) other;
    
    lastComparison = Boolean.valueOf(isSetEstimatedSize()).compareTo(typedOther.isSetEstimatedSize());
    if (lastComparison != 0) {
      return lastComparison;
    }
    if (isSetEstimatedSize()) {
      lastComparison = TBaseHelper.compareTo(this.estimatedSize, typedOther.estimatedSize);
      if (lastComparison != 0) {
        return lastComparison;
      }
    }
    return 0;
  }
  
  public void read(TProtocol iprot) throws TException {
    TField field;
    iprot.readStructBegin();
    while (true) {
      field = iprot.readFieldBegin();
      if (field.type == TType.STOP) {
        break;
      }
      switch (field.id) {
        case 1: // ESTIMATED_SIZE
          if (field.type == TType.I64) {
            this.estimatedSize = iprot.readI64();
            setEstimatedSizeIsSet(true);
          } else {
            TProtocolUtil.skip(iprot, field.type);
          }
          break;
        default:
          TProtocolUtil.skip(iprot, field.type);
      }
      iprot.readFieldEnd();
    }
    iprot.readStructEnd();
    
    // check for required fields of primitive type, which can't be checked in the validate method
    validate();
  }
  
  public void write(TProtocol oprot) throws TException {
    validate();
    
    oprot.writeStructBegin(STRUCT_DESC);
    oprot.writeFieldBegin(ESTIMATED_SIZE_FIELD_DESC);
    oprot.writeI64(this.estimatedSize);
    oprot.writeFieldEnd();
    oprot.writeFieldStop();
    oprot.writeStructEnd();
  }
  
  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder("MapFileInfo(");
    sb.append("estimatedSize:");
    sb.append(this.estimatedSize);
    sb.append(")");
    return sb.toString();
  }
  
  public void validate() throws TException {
    // check for required fields
  }
  
}