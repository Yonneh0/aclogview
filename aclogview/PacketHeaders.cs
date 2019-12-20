using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
namespace aclogview {
    public class ProtoHeader {
        public uint seqID_;       // Sequence number
        public uint header_;      // Bitmask for which optional headers are present
        public uint checksum_;    // CRC
        public ushort recID_;     // Recipient ID - maps to the receivers_ (aka packet stream? can have different ip per receiver)
        public ushort interval_;  // time since last recieved a packet
        public ushort datalen_;   // Length of data in the packet, excluding this header
        public ushort iteration_; // the table, another bucketing mechanism, logical grouping
        public uint headerChecksum;
        public uint payloadChecksum;
        public ProtoHeader(BinaryReader binaryReader) {
            seqID_ = binaryReader.ReadUInt32();
            header_ = binaryReader.ReadUInt32();
            checksum_ = binaryReader.ReadUInt32();
            recID_ = binaryReader.ReadUInt16();
            interval_ = binaryReader.ReadUInt16();
            datalen_ = binaryReader.ReadUInt16();
            iteration_ = binaryReader.ReadUInt16();
            headerChecksum = (uint)0x00140000 + seqID_ + header_ + (uint)0xBADD70DD + ((uint)recID_) + ((uint)interval_ << 16) + ((uint)datalen_) + ((uint)iteration_ << 16);
            payloadChecksum = 0;
        }
    }

    public class sockaddr_in {
        public short sin_family;
        public ushort sin_port;
        public byte[] sin_addr = new byte[4];
        public byte[] sin_zero = new byte[8];

        public static sockaddr_in read(BinaryReader binaryReader) {
            sockaddr_in newObj = new sockaddr_in();
            newObj.sin_family = binaryReader.ReadInt16();
            newObj.sin_port = binaryReader.ReadUInt16();
            newObj.sin_addr = binaryReader.ReadBytes(4);
            newObj.sin_zero = binaryReader.ReadBytes(8);
            return newObj;
        }
    }

    public class BlobFragHeader_t {
        public ulong blobID;
        public ushort numFrags;
        public ushort blobFragSize;
        public ushort blobNum;
        public ushort queueID;

        public BlobFragHeader_t(BinaryReader binaryReader) {
            try {
                blobID = binaryReader.ReadUInt64();
                numFrags = binaryReader.ReadUInt16();
                blobFragSize = binaryReader.ReadUInt16();
                blobNum = binaryReader.ReadUInt16();
                queueID = binaryReader.ReadUInt16();
            } catch { }
        }
    }

    class OrderHdr {
        public uint stamp; // Ordering number

        public OrderHdr(BinaryReader binaryReader) {
            try { stamp = binaryReader.ReadUInt32(); } catch { }
        }
    }

    class WOrderHdr {
        public uint id;    // GUID of object to apply to
        public uint stamp; // Ordering number

        public WOrderHdr(BinaryReader binaryReader) {
            try {
                id = binaryReader.ReadUInt32();
                stamp = binaryReader.ReadUInt32();
            } catch { }
        }
    }
}
