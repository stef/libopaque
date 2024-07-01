package io.opaque;

public class OpaqueIds {
    public OpaqueIds() {}
    public OpaqueIds(byte[] idU_, byte[] idS_) {
        idU = idU_;
        idS = idS_;
    }

    public byte[] idU;
    public byte[] idS;
}