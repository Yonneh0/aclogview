using System.IO;

class PcapHeader {
    public uint magicNumber;
    public ushort versionMajor;
    public ushort versionMinor;
    public uint thisZone;
    public uint sigFigs;
    public uint snapLen;
    public uint network;

    public PcapHeader(BinaryReader binaryReader) {
        magicNumber = binaryReader.ReadUInt32();
        versionMajor = binaryReader.ReadUInt16();
        versionMinor = binaryReader.ReadUInt16();
        thisZone = binaryReader.ReadUInt32();
        sigFigs = binaryReader.ReadUInt32();
        snapLen = binaryReader.ReadUInt32();
        network = binaryReader.ReadUInt32();
    }
}

class PcapRecordHeader {
    public uint tsSec;
    public uint tsUsec;
    public uint inclLen;
    public uint origLen;

    public PcapRecordHeader(BinaryReader binaryReader) {
        tsSec = binaryReader.ReadUInt32();
        tsUsec = binaryReader.ReadUInt32();
        inclLen = binaryReader.ReadUInt32();
        origLen = binaryReader.ReadUInt32();
    }
}

class PcapngBlockHeader {
    public uint blockType;
    public uint blockTotalLength;
    public uint interfaceID;
    public uint tsHigh;
    public uint tsLow;
    public uint capturedLen;
    public uint packetLen;

    public PcapngBlockHeader(BinaryReader binaryReader) {

        blockType = binaryReader.ReadUInt32();
        blockTotalLength = binaryReader.ReadUInt32();
        if (blockType == 6) {
            interfaceID = binaryReader.ReadUInt32();
            tsHigh = binaryReader.ReadUInt32();
            tsLow = binaryReader.ReadUInt32();
            capturedLen = binaryReader.ReadUInt32();
            packetLen = binaryReader.ReadUInt32();
        } else if (blockType == 3) {
            packetLen = binaryReader.ReadUInt32();
            capturedLen = blockTotalLength - 16;
        }
    }
}

class EthernetHeader {
    public byte[] dest;
    public byte[] source;
    public ushort proto;

    public EthernetHeader(BinaryReader binaryReader) {
        dest = binaryReader.ReadBytes(6);
        source = binaryReader.ReadBytes(6);
        proto = binaryReader.ReadUInt16();
    }
}

class IpAddress {
    public byte[] bytes;

    public IpAddress(BinaryReader binaryReader) {
        bytes = binaryReader.ReadBytes(4);
    }

    public override string ToString()
    {
        if (bytes.Length == 4)
            return bytes[0] + "." + bytes[1] + "." + bytes[2] + "." + bytes[3];

        return base.ToString();
    }
}

class IpHeader {
    public byte verIhl;
    public byte tos;
    public ushort tLen;
    public ushort identification;
    public ushort flagsFo;
    public byte ttl;
    public byte proto;
    public ushort crc;
    public IpAddress sAddr;
    public IpAddress dAddr;

    public IpHeader(BinaryReader binaryReader) {
        verIhl = binaryReader.ReadByte();
        tos = binaryReader.ReadByte();
        tLen = binaryReader.ReadUInt16();
        identification = binaryReader.ReadUInt16();
        flagsFo = binaryReader.ReadUInt16();
        ttl = binaryReader.ReadByte();
        proto = binaryReader.ReadByte();
        crc = binaryReader.ReadUInt16();
        sAddr = new IpAddress(binaryReader);
        dAddr = new IpAddress(binaryReader);
    }
}

class UdpHeader {
    public ushort sPort;
    public ushort dPort;
    public ushort len;
    public ushort crc;

    public UdpHeader(BinaryReader binaryReader) {
        sPort = Util.byteSwapped(binaryReader.ReadUInt16());
        dPort = Util.byteSwapped(binaryReader.ReadUInt16());
        len = Util.byteSwapped(binaryReader.ReadUInt16());
        crc = Util.byteSwapped(binaryReader.ReadUInt16());
    }
}
