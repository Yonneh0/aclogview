using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Linq;

namespace aclogview
{
    static class PCapReader
    {
        public static List<PacketRecord> LoadPcap(string fileName, bool asMessages, ref bool abort, out bool isPcapng)
        {
            using (FileStream fileStream = new FileStream(fileName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                using (BinaryReader binaryReader = new BinaryReader(fileStream))
                {
                    uint magicNumber = binaryReader.ReadUInt32();

                    binaryReader.BaseStream.Position = 0;

                    if (magicNumber == 0xA1B2C3D4 || magicNumber == 0xD4C3B2A1)
                    {
                        isPcapng = false;
                        return loadPcapPacketRecords(binaryReader, asMessages, ref abort);
                    }

                    isPcapng = true;
                    return loadPcapngPacketRecords(binaryReader, asMessages, ref abort);
                }
            }
        }

        private class FragNumComparer : IComparer<BlobFrag>
        {
            int IComparer<BlobFrag>.Compare(BlobFrag a, BlobFrag b)
            {
                if (a.memberHeader_.blobNum > b.memberHeader_.blobNum)
                    return 1;
                if (a.memberHeader_.blobNum < b.memberHeader_.blobNum)
                    return -1;
                return 0;
            }
        }

        private static bool addPacketIfFinished(List<PacketRecord> finishedRecords, PacketRecord record)
        {
            record.frags.Sort(new FragNumComparer());

            // Make sure all fragments are present
            if (record.frags.Count < record.frags[0].memberHeader_.numFrags
                || record.frags[0].memberHeader_.blobNum != 0
                || record.frags[record.frags.Count - 1].memberHeader_.blobNum != record.frags[0].memberHeader_.numFrags - 1)
            {
                return false;
            }

            record.index = finishedRecords.Count;

            // Remove duplicate fragments
            int index = 0;
            while (index < record.frags.Count - 1)
            {
                if (record.frags[index].memberHeader_.blobNum == record.frags[index + 1].memberHeader_.blobNum)
                    record.frags.RemoveAt(index);
                else
                    index++;
            }

            int totalMessageSize = 0;
            foreach (BlobFrag frag in record.frags)
            {
                totalMessageSize += frag.dat_.Length;
            }

            record.data = new byte[totalMessageSize];
            int offset = 0;
            foreach (BlobFrag frag in record.frags)
            {
                Buffer.BlockCopy(frag.dat_, 0, record.data, offset, frag.dat_.Length);
                offset += frag.dat_.Length;
            }

            finishedRecords.Add(record);

            return true;
        }

        private static PcapRecordHeader readPcapRecordHeader(BinaryReader binaryReader, int curPacket)
        {
            if (binaryReader.BaseStream.Length - binaryReader.BaseStream.Position < 16)
            {
                throw new InvalidDataException("Stream cut short (packet " + curPacket + "), stopping read: " + (binaryReader.BaseStream.Length - binaryReader.BaseStream.Position));
            }

            PcapRecordHeader recordHeader = PcapRecordHeader.read(binaryReader);

            if (recordHeader.inclLen > 5000)
            {
                throw new InvalidDataException("Enormous packet (packet " + curPacket + "), stopping read: " + recordHeader.inclLen);
            }

            // Make sure there's enough room for an ethernet header
            if (recordHeader.inclLen < 14)
            {
                binaryReader.BaseStream.Position += recordHeader.inclLen;
                return null;
            }

            return recordHeader;
        }

        private static List<PacketRecord> loadPcapPacketRecords(BinaryReader binaryReader, bool asMessages, ref bool abort)
        {
            /*PcapHeader pcapHeader = */PcapHeader.read(binaryReader);

            List<PacketRecord> results = new List<PacketRecord>();

            int curPacket = 0;

            Dictionary<ulong, PacketRecord> incompletePacketMap = new Dictionary<ulong, PacketRecord>();

            while (binaryReader.BaseStream.Position != binaryReader.BaseStream.Length)
            {
                if (abort)
                    break;

                PcapRecordHeader recordHeader;
                try
                {
                    recordHeader = readPcapRecordHeader(binaryReader, curPacket);

                    if (recordHeader == null)
                    {
                        continue;
                    }
                }
                catch (InvalidDataException e)
                {
                    break;
                }

                long packetStartPos = binaryReader.BaseStream.Position;

                try
                {
                    if (asMessages)
                    {
                        if (!readMessageData(binaryReader, recordHeader.inclLen, recordHeader.tsSec, recordHeader.tsUsec, results, incompletePacketMap, false))
                            break;
                    }
                    else
                    {
                        var packetRecord = readPacketData(binaryReader, recordHeader.inclLen, recordHeader.tsSec, recordHeader.tsUsec, curPacket, false);

                        if (packetRecord == null)
                            break;

                        results.Add(packetRecord);
                    }

                    curPacket++;
                }
                catch (Exception e)
                {
                    binaryReader.BaseStream.Position += recordHeader.inclLen - (binaryReader.BaseStream.Position - packetStartPos);
                }
            }
            CryptoValid = false;
            SendGenerator = null;
            RecvGenerator = null;
            return results;
        }

        private static PcapngBlockHeader readPcapngBlockHeader(BinaryReader binaryReader, int curPacket)
        {
            if (binaryReader.BaseStream.Length - binaryReader.BaseStream.Position < 8)
            {
                throw new InvalidDataException("Stream cut short (packet " + curPacket + "), stopping read: " + (binaryReader.BaseStream.Length - binaryReader.BaseStream.Position));
            }

            long blockStartPos = binaryReader.BaseStream.Position;

            PcapngBlockHeader blockHeader = PcapngBlockHeader.read(binaryReader);

            if (blockHeader.capturedLen > 50000)
            {
                throw new InvalidDataException("Enormous packet (packet " + curPacket + "), stopping read: " + blockHeader.capturedLen);
            }

            // Make sure there's enough room for an ethernet header
            if (blockHeader.capturedLen < 14)
            {
                binaryReader.BaseStream.Position += blockHeader.blockTotalLength - (binaryReader.BaseStream.Position - blockStartPos);
                return null;
            }

            return blockHeader;
        }

        private static List<PacketRecord> loadPcapngPacketRecords(BinaryReader binaryReader, bool asMessages, ref bool abort)
        {
            List<PacketRecord> results = new List<PacketRecord>();

            int curPacket = 0;

            Dictionary<ulong, PacketRecord> incompletePacketMap = new Dictionary<ulong, PacketRecord>();

            while (binaryReader.BaseStream.Position != binaryReader.BaseStream.Length)
            {
                if (abort)
                    break;

                long blockStartPos = binaryReader.BaseStream.Position;

                PcapngBlockHeader blockHeader;
                try
                {
                    blockHeader = readPcapngBlockHeader(binaryReader, curPacket);

                    if (blockHeader == null)
                    {
                        continue;
                    }
                }
                catch (InvalidDataException e)
                {
                    break;
                }

                long packetStartPos = binaryReader.BaseStream.Position;

                try
                {
                    if (asMessages)
                    {
                        if (!readMessageData(binaryReader, blockHeader.capturedLen, blockHeader.tsLow, blockHeader.tsHigh, results, incompletePacketMap, true))
                            break;
                    }
                    else
                    {
                        var packetRecord = readPacketData(binaryReader, blockHeader.capturedLen, blockHeader.tsLow, blockHeader.tsHigh, curPacket, true);

                        if (packetRecord == null)
                            break;

                        results.Add(packetRecord);
                    }

                    curPacket++;
                }
                catch (Exception e)
                {
                    binaryReader.BaseStream.Position += blockHeader.capturedLen - (binaryReader.BaseStream.Position - packetStartPos);
                }

                binaryReader.BaseStream.Position += blockHeader.blockTotalLength - (binaryReader.BaseStream.Position - blockStartPos);
            }
            CryptoValid = false;
            SendGenerator = null;
            RecvGenerator = null;

            return results;
        }

        private static (IpHeader, bool, uint) readNetworkHeaders(BinaryReader binaryReader)
        {
            EthernetHeader ethernetHeader = EthernetHeader.read(binaryReader);

            // Skip non-IP packets
            if (ethernetHeader.proto != 8)
            {
                throw new InvalidDataException();
            }

            IpHeader ipHeader = IpHeader.read(binaryReader);

            // Skip non-UDP packets
            if (ipHeader.proto != 17)
            {
                throw new InvalidDataException();
            }

            UdpHeader udpHeader = UdpHeader.read(binaryReader);

            bool isSend = (udpHeader.dPort >= 9000 && udpHeader.dPort <= 10013);
            bool isRecv = (udpHeader.sPort >= 9000 && udpHeader.sPort <= 10013);

            uint port = 0;
            if (isSend)
                port = udpHeader.dPort;
            else if (isRecv)
                port = udpHeader.sPort;

            // Skip non-AC-port packets
            if (!isSend && !isRecv)
            {
                throw new InvalidDataException();
            }

            return (ipHeader, isSend, port);
        }

        private static PacketRecord readPacketData(BinaryReader binaryReader, long len, uint ts1, uint ts2, int curPacket, bool isPcapng)
        {
            // Begin reading headers
            long packetStartPos = binaryReader.BaseStream.Position;

            (IpHeader ipHeader, bool isSend, uint port) = readNetworkHeaders(binaryReader);

            long headersSize = binaryReader.BaseStream.Position - packetStartPos;

            // Begin reading non-header packet content
            StringBuilder packetHeadersStr = new StringBuilder();
            StringBuilder packetTypeStr = new StringBuilder();

            PacketRecord packet = new PacketRecord();

            packet.index = curPacket;

            packet.ipHeader = ipHeader;
            packet.ServerPort = port;

            packet.isSend = isSend;

            if (isPcapng)
            {
                packet.tsLow = ts1;
                packet.tsHigh = ts2;
            }
            else
            {
                packet.tsSec = ts1;
                packet.tsUsec = ts2;
            }

            packet.extraInfo = "";
            packet.data = binaryReader.ReadBytes((int)(len - headersSize));
			using (BinaryReader packetReader = new BinaryReader(new MemoryStream(packet.data)))
			{
				try
				{
					ProtoHeader pHeader = ProtoHeader.read(packetReader);
					
					packet.Seq = pHeader.seqID_;
					packet.Iteration = pHeader.iteration_;

					packet.optionalHeadersLen = readOptionalHeaders(pHeader.header_, packetHeadersStr, packetReader, packet.data, isSend);

					if (packetReader.BaseStream.Position == packetReader.BaseStream.Length)
						packetTypeStr.Append("<Header Only>");

					uint HAS_FRAGS_MASK = 0x4; // See SharedNet::SplitPacketData

					if ((pHeader.header_ & HAS_FRAGS_MASK) != 0)
					{
						while (packetReader.BaseStream.Position != packetReader.BaseStream.Length)
						{
							if (packetTypeStr.Length != 0)
								packetTypeStr.Append(" + ");

							BlobFrag newFrag = readFragment(packetReader);
							packet.frags.Add(newFrag);

							if (newFrag.memberHeader_.blobNum != 0)
							{
								packetTypeStr.Append($"FragData[{newFrag.memberHeader_.blobNum}]");
							}
							else
							{
								using (BinaryReader fragDataReader = new BinaryReader(new MemoryStream(newFrag.dat_)))
								{
									PacketOpcode opcode = Util.readOpcode(fragDataReader);
									packet.opcodes.Add(opcode);
									packetTypeStr.Append(opcode);
									packet.Queue = newFrag.memberHeader_.queueID;
								}
							}
						}
					}

					if (packetReader.BaseStream.Position != packetReader.BaseStream.Length)
						packet.extraInfo = "Didnt read entire packet! " + packet.extraInfo;
				}
				catch (OutOfMemoryException e)
				{
					//MessageBox.Show("Out of memory (packet " + curPacket + "), stopping read: " + e);
					return null;
				}
				catch (Exception e)
				{
					packet.extraInfo += "EXCEPTION: " + e.Message + " " + e.StackTrace;
				}
			}
            packet.packetHeadersStr = packetHeadersStr.ToString();
            packet.packetTypeStr = packetTypeStr.ToString();

            return packet;
        }

        private static bool readMessageData(BinaryReader binaryReader, long len, uint ts1, uint ts2, List<PacketRecord> results, Dictionary<ulong, PacketRecord> incompletePacketMap, bool isPcapng)
        {
            // Begin reading headers
            long packetStartPos = binaryReader.BaseStream.Position;

            (IpHeader ipHeader, bool isSend, uint port) = readNetworkHeaders(binaryReader);

            long headersSize = binaryReader.BaseStream.Position - packetStartPos;

            // Begin reading non-header packet content
            StringBuilder packetHeadersStr = new StringBuilder();
            StringBuilder packetTypeStr = new StringBuilder();

            PacketRecord packet = null;
            byte[] packetData = binaryReader.ReadBytes((int)(len - headersSize));
			using (BinaryReader packetReader = new BinaryReader(new MemoryStream(packetData)))
			{
				try
				{
					ProtoHeader pHeader = ProtoHeader.read(packetReader);

					uint HAS_FRAGS_MASK = 0x4; // See SharedNet::SplitPacketData

					if ((pHeader.header_ & HAS_FRAGS_MASK) != 0)
					{
						readOptionalHeaders(pHeader.header_, packetHeadersStr, packetReader, packetData, isSend);

						while (packetReader.BaseStream.Position != packetReader.BaseStream.Length)
						{
							BlobFrag newFrag = readFragment(packetReader);

							ulong blobID = newFrag.memberHeader_.blobID;
							if (incompletePacketMap.ContainsKey(blobID))
							{
								packet = incompletePacketMap[newFrag.memberHeader_.blobID];
							}
							else
							{
								packet = new PacketRecord();
								incompletePacketMap.Add(blobID, packet);
								packet.Seq = pHeader.seqID_;
								packet.Queue = newFrag.memberHeader_.queueID;
                                packet.Iteration = pHeader.iteration_;
                            }

							if (newFrag.memberHeader_.blobNum == 0)
                            {
                                packet.ipHeader = ipHeader;
                                packet.ServerPort = port;
                                packet.isSend = isSend;

							    if (isPcapng)
							    {
							        packet.tsLow = ts1;
							        packet.tsHigh = ts2;
							    }
							    else
							    {
							        packet.tsSec = ts1;
							        packet.tsUsec = ts2;
                                }

								packet.extraInfo = "";
								packet.Seq = pHeader.seqID_;
								packet.Queue = newFrag.memberHeader_.queueID;
                                packet.Iteration = pHeader.iteration_;

                                using (BinaryReader fragDataReader = new BinaryReader(new MemoryStream(newFrag.dat_)))
								{
									PacketOpcode opcode = Util.readOpcode(fragDataReader);
									packet.opcodes.Add(opcode);
									packet.packetTypeStr = opcode.ToString();
								}
							}

							packet.packetHeadersStr += packetHeadersStr.ToString();

							packet.frags.Add(newFrag);

							if (addPacketIfFinished(results, packet))
							{
								incompletePacketMap.Remove(blobID);
							}
						}

						if (packetReader.BaseStream.Position != packetReader.BaseStream.Length)
							packet.extraInfo = "Didnt read entire packet! " + packet.extraInfo;
					}
				}
				catch (OutOfMemoryException e)
				{
					//MessageBox.Show("Out of memory (packet " + curPacket + "), stopping read: " + e);
					return false;
				}
				catch (Exception e)
				{
					packet.extraInfo += "EXCEPTION: " + e.Message + " " + e.StackTrace;
				}
			}
            return true;
        }

        private static BlobFrag readFragment(BinaryReader packetReader)
        {
            BlobFrag newFrag = new BlobFrag();
            newFrag.memberHeader_ = BlobFragHeader_t.read(packetReader);
            newFrag.dat_ = packetReader.ReadBytes(newFrag.memberHeader_.blobFragSize - 16); // 16 == size of frag header

            return newFrag;
        }

        [Flags]
        public enum ACEPacketHeaderFlags : uint  //ACE
        {
            None = 0x00000000,
            RESEND = 0x00000001,
            EncCRC = 0x00000002,     // can't be paired with 0x00000001, see FlowQueue::DequeueAck
            FRAG = 0x00000004,
            ServerSwitch = 0x00000100,          // Server Switch
            LogonServerAddr = 0x00000200,       // Logon Server Addr
            EmptyHeader1 = 0x00000400,          // Empty Header 1
            Referral = 0x00000800,              // Referral
            NAK = 0x00001000,     // Nak
            EACK = 0x00002000,      // Empty Ack
            PAK = 0x00004000,           // Pak
            Disconnect = 0x00008000,            // Empty Header 2
            LoginRequest = 0x00010000,          // Login
            WorldLoginRequest = 0x00020000,     // ULong 1
            ConnectRequest = 0x00040000,        // Connect
            ConnectResponse = 0x00080000,       // ULong 2
            NetError = 0x00100000,              // Net Error
            NetErrorDisconnect = 0x00200000,    // Net Error Disconnect
            CICMDCommand = 0x00400000,          // ICmd
            TIME = 0x01000000,              // Time Sync
            PING = 0x02000000,           // Echo Request
            PONG = 0x04000000,          // Echo Response
            Flow = 0x08000000                   // Flow
        }

        public static uint Hash32(byte[] data, int length, int offset = 0) {
            uint checksum = (uint)length << 16;

            for (int i = 0; i < length && i + 4 <= length; i += 4)
                checksum += BitConverter.ToUInt32(data, offset + i);

            int shift = 3;
            int j = (length / 4) * 4;

            while (j < length)
                checksum += (uint)(data[offset + j++] << (8 * shift--));

            return checksum;
        }
        public static uint CalculateHash32(byte[] buf, int len) {
            uint original = 0;
            try {
                original = BitConverter.ToUInt32(buf, 0x08);
                buf[0x08] = 0xDD;
                buf[0x09] = 0x70;
                buf[0x0A] = 0xDD;
                buf[0x0B] = 0xBA;

                var checksum = Hash32(buf, len);
                buf[0x08] = (byte)(original & 0xFF);
                buf[0x09] = (byte)(original >> 8);
                buf[0x0A] = (byte)(original >> 16);
                buf[0x0B] = (byte)(original >> 24);
                return checksum;
            } catch { return 0xDEADBEEF; }
        }

        public static CryptoSystem SendGenerator { get; private set; }
        public static CryptoSystem RecvGenerator { get; private set; }
        public static bool CryptoValid = false;
        private static int readOptionalHeaders(uint header_, StringBuilder packetHeadersStr, BinaryReader packetReader, byte[] originalData, bool isSend)
        {
            long readStartPos = packetReader.BaseStream.Position;
            ACEPacketHeaderFlags header = (ACEPacketHeaderFlags)header_;
            List<string> result = new List<string>() { "" };

            if ((header & ACEPacketHeaderFlags.RESEND) != 0) {
                result.Add("RESEND");
            }
            if ((header & ACEPacketHeaderFlags.ServerSwitch) != 0) {
                uint ServerSwitchdwSeqNo = packetReader.ReadUInt32();
                uint ServerSwitchType = packetReader.ReadUInt32();
                result.Add($"ServerSwitch(seq:{ServerSwitchdwSeqNo},type:{ServerSwitchType})");
            }

            if ((header & ACEPacketHeaderFlags.LogonServerAddr) != 0) {
                short LogonServerAddrsin_family = packetReader.ReadInt16();
                ushort LogonServerAddrsin_port = packetReader.ReadUInt16();
                byte[] LogonServerAddrsin_addr = packetReader.ReadBytes(4);
                /*byte[] LogonServerAddrsin_zero =*/ packetReader.ReadBytes(8);
                result.Add($"LogonServerAddr({LogonServerAddrsin_family}::{LogonServerAddrsin_addr[0]}.{LogonServerAddrsin_addr[1]}.{LogonServerAddrsin_addr[2]}.{LogonServerAddrsin_addr[3]}:{LogonServerAddrsin_port})");
            }

            if ((header & ACEPacketHeaderFlags.EmptyHeader1) != 0) {
                result.Add("EmptyHeader1");
            }

            if ((header & ACEPacketHeaderFlags.Referral) != 0) {
                ulong ReferralQWCookie = packetReader.ReadUInt64();
                short Referralsin_family = packetReader.ReadInt16();
                ushort Referralsin_port = packetReader.ReadUInt16();
                byte[] Referralsin_addr = packetReader.ReadBytes(4);
                packetReader.ReadBytes(16);
                result.Add($"Referral(cookie:0x{ReferralQWCookie:X16}  {Referralsin_family}::{Referralsin_addr[0]}.{Referralsin_addr[1]}.{Referralsin_addr[2]}.{Referralsin_addr[3]}:{Referralsin_port})");
            }

            if ((header & ACEPacketHeaderFlags.NAK) != 0) {
                uint num = packetReader.ReadUInt32();
                StringBuilder naks = new StringBuilder($"NAK[{num}](");
                for (uint i = 0; i < num; ++i) {
                    if (i > 0) naks.Append(",");
                    naks.Append(packetReader.ReadUInt32());
                }
                result.Add($"{naks.ToString()})");
            }

            if ((header & ACEPacketHeaderFlags.EACK) != 0) {
                uint num = packetReader.ReadUInt32();
                StringBuilder naks = new StringBuilder($"EACK[{num}](");
                for (uint i = 0; i < num; ++i) {
                    if (i > 0) naks.Append(",");
                    naks.Append(packetReader.ReadUInt32());
                }
                result.Add($"{naks.ToString()})");
            }

            if ((header & ACEPacketHeaderFlags.PAK) != 0) {
                uint num = packetReader.ReadUInt32();
                result.Add($"PAK({num})");
            }

            if ((header & ACEPacketHeaderFlags.Disconnect) != 0) {
                result.Add("Disconnect");
            }

            if ((header & ACEPacketHeaderFlags.LoginRequest) != 0) {
                PStringChar ClientVersion = PStringChar.read(packetReader);
                int cbAuthData = packetReader.ReadInt32();
                packetReader.ReadBytes(cbAuthData);

                result.Add($"LoginRequest({ClientVersion}[{cbAuthData}])");
            }

            if ((header & ACEPacketHeaderFlags.WorldLoginRequest) != 0) {
                ulong m_Prim = packetReader.ReadUInt64();
                result.Add($"WorldLoginRequest(0x{m_Prim:X16})");
            }

            if ((header & ACEPacketHeaderFlags.ConnectRequest) != 0) {
                double ConnectRequestServerTime = packetReader.ReadDouble();
                ulong ConnectRequestCookie = packetReader.ReadUInt64();
                uint ConnectRequestNetID = packetReader.ReadUInt32();
                uint ConnectRequestOutgoingSeed = packetReader.ReadUInt32();
                uint ConnectRequestIncomingSeed = packetReader.ReadUInt32();
                /*uint ConnectRequestunk =*/ packetReader.ReadUInt32();

                RecvGenerator = new CryptoSystem(ConnectRequestOutgoingSeed);
                SendGenerator = new CryptoSystem(ConnectRequestIncomingSeed);
                CryptoValid = true;

                result.Add($"ConnectRequest(time:{Math.Round(ConnectRequestServerTime,5)},cookie:0x{ConnectRequestCookie:X16},netid:{ConnectRequestNetID},sendseed:0x{ConnectRequestIncomingSeed:X8},recvseed:0x{ConnectRequestOutgoingSeed:X8})");
            }

            if ((header & ACEPacketHeaderFlags.ConnectResponse) != 0) {
                ulong ConnectResponseCookie = packetReader.ReadUInt64();
                result.Add($"ConnectResponse(0x{ConnectResponseCookie:X16})");
            }

            if ((header & ACEPacketHeaderFlags.NetError) != 0) {
                uint m_stringID = packetReader.ReadUInt32();
                uint m_tableID = packetReader.ReadUInt32();
                result.Add($"NetError({m_stringID},{m_tableID})");
            }

            if ((header & ACEPacketHeaderFlags.NetErrorDisconnect) != 0) {
                uint m_stringID = packetReader.ReadUInt32();
                uint m_tableID = packetReader.ReadUInt32();
                result.Add($"NetErrorDisconnect({m_stringID},{m_tableID})");
            }

            if ((header & ACEPacketHeaderFlags.CICMDCommand) != 0) {
                uint Cmd = packetReader.ReadUInt32();
                uint Param = packetReader.ReadUInt32();
                result.Add($"CICMDCommand({Cmd:X8}=>{Param:X8})");
            }

            if ((header & ACEPacketHeaderFlags.TIME) != 0) {
                double m_time = packetReader.ReadDouble();
                result.Add($"TIME({Math.Round(m_time,5)})");
            }

            if ((header & ACEPacketHeaderFlags.PING) != 0) {
                float m_LocalTime = packetReader.ReadSingle();
                result.Add($"PING({Math.Round(m_LocalTime,5)})");
            }

            if ((header & ACEPacketHeaderFlags.PONG) != 0) {
                float LocalTime = packetReader.ReadSingle();
                float HoldingTime = packetReader.ReadSingle();
                result.Add($"PONG({Math.Round(LocalTime,5)} ++ {Math.Round(HoldingTime,5)})");
            }

            if ((header & ACEPacketHeaderFlags.Flow) != 0) {
                uint FlowCBDataRecvd = packetReader.ReadUInt32();
                ushort FlowInterval = packetReader.ReadUInt16();
                result.Add($"Flow(rcvd:{FlowCBDataRecvd},int:{FlowInterval})");
            }

            if ((header & ACEPacketHeaderFlags.FRAG) != 0) {
                result.Add($"FRAG");
            }
            int headersEndAt = (int)(packetReader.BaseStream.Position - readStartPos);

            //result[0] += $" {headerChecksum:X8} + {payloadChecksum:X8} =  {headerChecksum + payloadChecksum:X8} // {original:X8}";


            if ((header & ACEPacketHeaderFlags.EncCRC) != 0) {
                if (CryptoValid) {
                    if (!ValidateXORCRC(originalData,isSend,headersEndAt))
                        result[0] = $"(INVALID XOR CRC)";
                    else {
                        result[0] = $"(VALID XOR CRC)";
                    }
                } else
                    result[0] = $"(? XOR CRC)";

            } else {
                if (!ValidateCRC(originalData,headersEndAt))
                    result[0] = $"(INVALID CRC)";
                else
                    result[0] = $"(VALID CRC)";
            }

            if (result.Count != 0) packetHeadersStr.Append(result.Aggregate((a, b) => a + " | " + b));
            return (int)(packetReader.BaseStream.Position - readStartPos);
        }
        private static bool ValidateCRC(byte[] originalData,int headersEndAt) {
            try {
                uint original = BitConverter.ToUInt32(originalData, 0x08);
                uint Checksum = CalculateHash32(originalData, 0x14 + headersEndAt);
                Checksum += Hash32(originalData, BitConverter.ToInt16(originalData, 0x10) - headersEndAt, 0x14 + headersEndAt);
                if (original == Checksum) return true;
            } catch { }
            return false;
        }
        private static bool ValidateXORCRC(byte[] originalData, bool isSend, int headersEndAt) {
            uint original = BitConverter.ToUInt32(originalData, 0x08);
            uint headerChecksum = CalculateHash32(originalData, 0x14);
            uint payloadChecksum = Hash32(originalData, headersEndAt, 0x14);
            payloadChecksum += Hash32(originalData, BitConverter.ToInt16(originalData, 0x10) - headersEndAt, 0x14 + headersEndAt);
            uint xor;
            for (int i = 0; i < 32; i++) {
                try {
                    if (isSend) xor = SendGenerator.xors[i];
                    else xor = RecvGenerator.xors[i];
                    if (original == (xor ^ payloadChecksum) + headerChecksum) {
                        if (isSend) SendGenerator.Eat(xor);
                        else RecvGenerator.Eat(xor);
                        return true;
                    }
                } catch { }
            }
            return false;
        }
    }
    public class CryptoSystem {
        private uint seed;
        public Rand isaac;
        public List<uint> xors = new List<uint>(256);
        public uint Seed {
            get { return this.seed; }
            set { CreateRandomGen(value); }
        }

        public CryptoSystem(uint seed) {
            CreateRandomGen(seed);
        }

        private uint GetKey() {
            return unchecked((uint)isaac.val());
        }
        public void Eat(uint key) {
            xors.Remove(key);
            xors.Add(GetKey());
        }
        private void CreateRandomGen(uint seed) {
            this.seed = seed;
            int signed_seed = unchecked((int)seed);
            this.isaac = new Rand(signed_seed, signed_seed, signed_seed);
            xors = new List<uint>(256);
            for (int i = 0; i < 256; i++) xors.Add(GetKey());
        }
    }




    public class Rand {
        public const int SIZEL = 8;              /* log of size of rsl[] and mem[] */
        public const int SIZE = 1 << SIZEL;               /* size of rsl[] and mem[] */
        public const int MASK = (SIZE - 1) << 2;            /* for pseudorandom lookup */
        public int count;                           /* count through the results in rsl[] */
        public int[] rsl;                                /* the results given to the user */
        private int[] mem;                                   /* the internal state */
        private int a;                                              /* accumulator */
        private int b;                                          /* the last result */
        private int c;              /* counter, guarantees cycle is at least 2^^40 */


        /* no seed, equivalent to randinit(ctx,FALSE) in C */
        public Rand() {
            mem = new int[SIZE];
            rsl = new int[SIZE];
            Init(false);
        }

        public Rand(int a, int b, int c) {
            this.a = a;
            this.b = b;
            this.c = c;

            mem = new int[SIZE];
            rsl = new int[SIZE];
            Init(true);
        }

        /* equivalent to randinit(ctx, TRUE) after putting seed in randctx in C */
        public Rand(int[] seed) {
            mem = new int[SIZE];
            rsl = new int[SIZE];
            for (int i = 0; i < seed.Length; ++i) {
                rsl[i] = seed[i];
            }
            Init(true);
        }


        /* Generate 256 results.  This is a fast (not small) implementation. */
        public /*final*/ void Isaac() {
            int i, j, x, y;

            b += ++c;
            for (i = 0, j = SIZE / 2; i < SIZE / 2;) {
                x = mem[i];
                a ^= a << 13;
                a += mem[j++];
                mem[i] = y = mem[(x & MASK) >> 2] + a + b;
                rsl[i++] = b = mem[((y >> SIZEL) & MASK) >> 2] + x;

                x = mem[i];
                a ^= (int)((uint)a >> 6);
                a += mem[j++];
                mem[i] = y = mem[(x & MASK) >> 2] + a + b;
                rsl[i++] = b = mem[((y >> SIZEL) & MASK) >> 2] + x;

                x = mem[i];
                a ^= a << 2;
                a += mem[j++];
                mem[i] = y = mem[(x & MASK) >> 2] + a + b;
                rsl[i++] = b = mem[((y >> SIZEL) & MASK) >> 2] + x;

                x = mem[i];
                a ^= (int)((uint)a >> 16);
                a += mem[j++];
                mem[i] = y = mem[(x & MASK) >> 2] + a + b;
                rsl[i++] = b = mem[((y >> SIZEL) & MASK) >> 2] + x;
            }

            for (j = 0; j < SIZE / 2;) {
                x = mem[i];
                a ^= a << 13;
                a += mem[j++];
                mem[i] = y = mem[(x & MASK) >> 2] + a + b;
                rsl[i++] = b = mem[((y >> SIZEL) & MASK) >> 2] + x;

                x = mem[i];
                a ^= (int)((uint)a >> 6);
                a += mem[j++];
                mem[i] = y = mem[(x & MASK) >> 2] + a + b;
                rsl[i++] = b = mem[((y >> SIZEL) & MASK) >> 2] + x;

                x = mem[i];
                a ^= a << 2;
                a += mem[j++];
                mem[i] = y = mem[(x & MASK) >> 2] + a + b;
                rsl[i++] = b = mem[((y >> SIZEL) & MASK) >> 2] + x;

                x = mem[i];
                a ^= (int)((uint)a >> 16);
                a += mem[j++];
                mem[i] = y = mem[(x & MASK) >> 2] + a + b;
                rsl[i++] = b = mem[((y >> SIZEL) & MASK) >> 2] + x;
            }
        }


        /* initialize, or reinitialize, this instance of rand */
        public /*final*/ void Init(bool flag) {
            int i;
            int a, b, c, d, e, f, g, h;
            a = b = c = d = e = f = g = h = unchecked((int)0x9e3779b9);                        /* the golden ratio */

            for (i = 0; i < 4; ++i) {
                a ^= b << 11; d += a; b += c;
                b ^= (int)((uint)c >> 2); e += b; c += d;
                c ^= d << 8; f += c; d += e;
                d ^= (int)((uint)e >> 16); g += d; e += f;
                e ^= f << 10; h += e; f += g;
                f ^= (int)((uint)g >> 4); a += f; g += h;
                g ^= h << 8; b += g; h += a;
                h ^= (int)((uint)a >> 9); c += h; a += b;
            }

            for (i = 0; i < SIZE; i += 8) {              /* fill in mem[] with messy stuff */
                if (flag) {
                    a += rsl[i]; b += rsl[i + 1]; c += rsl[i + 2]; d += rsl[i + 3];
                    e += rsl[i + 4]; f += rsl[i + 5]; g += rsl[i + 6]; h += rsl[i + 7];
                }
                a ^= b << 11; d += a; b += c;
                b ^= (int)((uint)c >> 2); e += b; c += d;
                c ^= d << 8; f += c; d += e;
                d ^= (int)((uint)e >> 16); g += d; e += f;
                e ^= f << 10; h += e; f += g;
                f ^= (int)((uint)g >> 4); a += f; g += h;
                g ^= h << 8; b += g; h += a;
                h ^= (int)((uint)a >> 9); c += h; a += b;
                mem[i] = a; mem[i + 1] = b; mem[i + 2] = c; mem[i + 3] = d;
                mem[i + 4] = e; mem[i + 5] = f; mem[i + 6] = g; mem[i + 7] = h;
            }

            if (flag) {           /* second pass makes all of seed affect all of mem */
                for (i = 0; i < SIZE; i += 8) {
                    a += mem[i]; b += mem[i + 1]; c += mem[i + 2]; d += mem[i + 3];
                    e += mem[i + 4]; f += mem[i + 5]; g += mem[i + 6]; h += mem[i + 7];
                    a ^= b << 11; d += a; b += c;
                    b ^= (int)((uint)c >> 2); e += b; c += d;
                    c ^= d << 8; f += c; d += e;
                    d ^= (int)((uint)e >> 16); g += d; e += f;
                    e ^= f << 10; h += e; f += g;
                    f ^= (int)((uint)g >> 4); a += f; g += h;
                    g ^= h << 8; b += g; h += a;
                    h ^= (int)((uint)a >> 9); c += h; a += b;
                    mem[i] = a; mem[i + 1] = b; mem[i + 2] = c; mem[i + 3] = d;
                    mem[i + 4] = e; mem[i + 5] = f; mem[i + 6] = g; mem[i + 7] = h;
                }
            }

            Isaac();
            count = SIZE;
        }


        /* Call rand.val() to get a random value */
        public /*final*/ int val() {
            if (0 == count--) {
                Isaac();
                count = SIZE - 1;
            }
            return rsl[count];
        }

        //public static void main(String[] args) {
        //  int[]  seed = new int[256];
        //  Rand x = new Rand(seed);
        //  for (int i=0; i<2; ++i) {
        //    x.Isaac();
        //    for (int j=0; j<Rand.SIZE; ++j) {
        //  //String z = Integer.toHexString(x.rsl[j]);
        //  //while (z.length() < 8) z = "0"+z;
        //  Console.WriteLine("{0:X8}", x.rsl[j]);
        //      if ((j&7)==7) Console.WriteLine("");
        //    }
        //  }
        //}
    }

}
