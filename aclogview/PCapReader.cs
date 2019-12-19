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
            SendCrypto.Clear();
            RecvCrypto.Clear();
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
            SendCrypto.Clear();
            RecvCrypto.Clear();

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
					ProtoHeader pHeader = new ProtoHeader(packetReader);
					
					packet.Seq = pHeader.seqID_;
					packet.Iteration = pHeader.iteration_;
                    packet.RecID = pHeader.recID_;

					packet.optionalHeadersLen = readOptionalHeaders(pHeader, packetHeadersStr, packetReader, packet.data, isSend);

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
					ProtoHeader pHeader = new ProtoHeader(packetReader);

					uint HAS_FRAGS_MASK = 0x4; // See SharedNet::SplitPacketData

					if ((pHeader.header_ & HAS_FRAGS_MASK) != 0)
					{
						readOptionalHeaders(pHeader, packetHeadersStr, packetReader, packetData, isSend);

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
                                packet.RecID = pHeader.recID_;
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
                                packet.RecID = pHeader.recID_;

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

        public static Dictionary<ushort, ICryptoSystem> SendCrypto = new Dictionary<ushort, ICryptoSystem>();
        public static Dictionary<ushort, ICryptoSystem> RecvCrypto = new Dictionary<ushort, ICryptoSystem>();
        private static int readOptionalHeaders(ProtoHeader pHeader, StringBuilder packetHeadersStr, BinaryReader packetReader, byte[] originalData, bool isSend)
        {
            long readStartPos = packetReader.BaseStream.Position;
            ACEPacketHeaderFlags header = (ACEPacketHeaderFlags)pHeader.header_;

            List<string> result = new List<string>() { "" }; // leave the first slot free for CRC/XOR status

            if ((header & ACEPacketHeaderFlags.RESEND) != 0) {
                result.Add("RESEND");
            }
            if ((header & ACEPacketHeaderFlags.ServerSwitch) != 0) {
                pHeader.payloadChecksum += Crypto.Hash32(originalData, 8, 0x14 + (int)(packetReader.BaseStream.Position - readStartPos));
                uint ServerSwitchdwSeqNo = packetReader.ReadUInt32();
                uint ServerSwitchType = packetReader.ReadUInt32();
                result.Add($"ServerSwitch(seq:{ServerSwitchdwSeqNo},type:{ServerSwitchType})");
            }

            if ((header & ACEPacketHeaderFlags.LogonServerAddr) != 0) {
                pHeader.payloadChecksum += Crypto.Hash32(originalData, 16, 0x14 + (int)(packetReader.BaseStream.Position - readStartPos));
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
                pHeader.payloadChecksum += Crypto.Hash32(originalData, 32, 0x14 + (int)(packetReader.BaseStream.Position - readStartPos));
                ulong ReferralQWCookie = packetReader.ReadUInt64();
                short Referralsin_family = packetReader.ReadInt16();
                ushort Referralsin_port = packetReader.ReadUInt16();
                byte[] Referralsin_addr = packetReader.ReadBytes(4);
                packetReader.ReadBytes(16);
                result.Add($"Referral(cookie:0x{ReferralQWCookie:X16}  {Referralsin_family}::{Referralsin_addr[0]}.{Referralsin_addr[1]}.{Referralsin_addr[2]}.{Referralsin_addr[3]}:{Referralsin_port})");
            }

            if ((header & ACEPacketHeaderFlags.NAK) != 0) {
                uint num = packetReader.ReadUInt32();
                pHeader.payloadChecksum += Crypto.Hash32(originalData, 4 + ((int)num * 4), 0x10 + (int)(packetReader.BaseStream.Position - readStartPos));
                StringBuilder naks = new StringBuilder($"NAK[{num}](");
                for (uint i = 0; i < num; ++i) {
                    if (i > 0) naks.Append(",");
                    naks.Append(packetReader.ReadUInt32());
                }
                result.Add($"{naks.ToString()})");
            }

            if ((header & ACEPacketHeaderFlags.EACK) != 0) {
                uint num = packetReader.ReadUInt32();
                pHeader.payloadChecksum += Crypto.Hash32(originalData, 4 + ((int)num * 4), 0x10 + (int)(packetReader.BaseStream.Position - readStartPos));
                StringBuilder naks = new StringBuilder($"EACK[{num}](");
                for (uint i = 0; i < num; ++i) {
                    if (i > 0) naks.Append(",");
                    naks.Append(packetReader.ReadUInt32());
                }
                result.Add($"{naks.ToString()})");
            }

            if ((header & ACEPacketHeaderFlags.PAK) != 0) {
                pHeader.payloadChecksum += Crypto.Hash32(originalData, 4, 0x14 + (int)(packetReader.BaseStream.Position - readStartPos));
                uint num = packetReader.ReadUInt32();
                result.Add($"PAK({num})");
            }

            if ((header & ACEPacketHeaderFlags.Disconnect) != 0) {
                result.Add("Disconnect");
            }

            if ((header & ACEPacketHeaderFlags.LoginRequest) != 0) {
                int Start = (int)(packetReader.BaseStream.Position);
                PStringChar ClientVersion = PStringChar.read(packetReader);
                int cbAuthData = packetReader.ReadInt32();

                packetReader.ReadBytes(cbAuthData);
                pHeader.payloadChecksum += Crypto.Hash32(originalData, (int)(packetReader.BaseStream.Position - Start), 0x14 + (Start - (int)readStartPos));

                result.Add($"LoginRequest({ClientVersion}[{cbAuthData}])"); // not parsing this, to keep usernames/passwords out of screenshots
            }

            if ((header & ACEPacketHeaderFlags.WorldLoginRequest) != 0) {
                pHeader.payloadChecksum += Crypto.Hash32(originalData, 8, 0x14 + (int)(packetReader.BaseStream.Position - readStartPos));
                ulong m_Prim = packetReader.ReadUInt64();
                result.Add($"WorldLoginRequest(0x{m_Prim:X16})");
            }

            if ((header & ACEPacketHeaderFlags.ConnectRequest) != 0) {
                pHeader.payloadChecksum += Crypto.Hash32(originalData, 32, 0x14 + (int)(packetReader.BaseStream.Position - readStartPos));
                double ConnectRequestServerTime = packetReader.ReadDouble();
                /* ulong ConnectRequestCookie = */ packetReader.ReadUInt64();
                uint ConnectRequestNetID = packetReader.ReadUInt32();
                uint ConnectRequestIncomingSeed = packetReader.ReadUInt32();
                uint ConnectRequestOutgoingSeed = packetReader.ReadUInt32();
                /*uint ConnectRequestunk =*/ packetReader.ReadUInt32();
                if (RecvCrypto.ContainsKey(pHeader.recID_)) {
                    result.Add($"Recv Crypto reset {pHeader.recID_}");
                    RecvCrypto.Remove(pHeader.recID_); // Hello GC!
                }
                if (SendCrypto.ContainsKey((ushort)ConnectRequestNetID)) {
                    result.Add($"Crypto reset {ConnectRequestNetID}");
                    SendCrypto.Remove((ushort)ConnectRequestNetID); // Hello GC!
                }
                RecvCrypto.Add(pHeader.recID_, new CryptoSystem(ConnectRequestIncomingSeed, ISAACProvider.Rand)); SendCrypto.Add((ushort)ConnectRequestNetID, new CryptoSystem(ConnectRequestOutgoingSeed, ISAACProvider.Rand));
                //RecvCrypto.Add(pHeader.recID_, new CryptoSystem(ConnectRequestIncomingSeed, ISAACProvider.Rand2)); SendCrypto.Add((ushort)ConnectRequestNetID, new CryptoSystem(ConnectRequestOutgoingSeed, ISAACProvider.Rand2));
                //RecvCrypto.Add(pHeader.recID_, new CryptoSystem2(ConnectRequestIncomingSeed, ISAACProvider.Rand)); SendCrypto.Add((ushort)ConnectRequestNetID, new CryptoSystem2(ConnectRequestOutgoingSeed, ISAACProvider.Rand));
                //RecvCrypto.Add(pHeader.recID_, new CryptoSystem2(ConnectRequestIncomingSeed, ISAACProvider.Rand2)); SendCrypto.Add((ushort)ConnectRequestNetID, new CryptoSystem2(ConnectRequestOutgoingSeed, ISAACProvider.Rand2));

                result.Add($"ConnectRequest(rec:{pHeader.recID_},time:{Math.Round(ConnectRequestServerTime,5)},net:{ConnectRequestNetID},sendseed:0x{ConnectRequestIncomingSeed:X8},recvseed:0x{ConnectRequestOutgoingSeed:X8})");
            }

            if ((header & ACEPacketHeaderFlags.ConnectResponse) != 0) {
                pHeader.payloadChecksum += Crypto.Hash32(originalData, 8, 0x14 + (int)(packetReader.BaseStream.Position - readStartPos));
                /* ulong ConnectResponseCookie = */ packetReader.ReadUInt64();
                result.Add($"ConnectResponse");
            }

            if ((header & ACEPacketHeaderFlags.NetError) != 0) {
                pHeader.payloadChecksum += Crypto.Hash32(originalData, 8, 0x14 + (int)(packetReader.BaseStream.Position - readStartPos));
                uint m_stringID = packetReader.ReadUInt32();
                uint m_tableID = packetReader.ReadUInt32();
                result.Add($"NetError({m_stringID},{m_tableID})");
            }

            if ((header & ACEPacketHeaderFlags.NetErrorDisconnect) != 0) {
                pHeader.payloadChecksum += Crypto.Hash32(originalData, 8, 0x14 + (int)(packetReader.BaseStream.Position - readStartPos));
                uint m_stringID = packetReader.ReadUInt32();
                uint m_tableID = packetReader.ReadUInt32();
                result.Add($"NetErrorDisconnect({m_stringID},{m_tableID})");
            }

            if ((header & ACEPacketHeaderFlags.CICMDCommand) != 0) {
                pHeader.payloadChecksum += Crypto.Hash32(originalData, 8, 0x14 + (int)(packetReader.BaseStream.Position - readStartPos));
                uint Cmd = packetReader.ReadUInt32();
                uint Param = packetReader.ReadUInt32();
                result.Add($"CICMDCommand({Cmd:X8}=>{Param:X8})");
            }

            if ((header & ACEPacketHeaderFlags.TIME) != 0) {
                pHeader.payloadChecksum += Crypto.Hash32(originalData, 8, 0x14 + (int)(packetReader.BaseStream.Position - readStartPos));
                double m_time = packetReader.ReadDouble();
                result.Add($"TIME({Math.Round(m_time,5)})");
            }

            if ((header & ACEPacketHeaderFlags.PING) != 0) {
                pHeader.payloadChecksum += Crypto.Hash32(originalData, 4, 0x14 + (int)(packetReader.BaseStream.Position - readStartPos));
                float m_LocalTime = packetReader.ReadSingle();
                result.Add($"PING({Math.Round(m_LocalTime,5)})");
            }

            if ((header & ACEPacketHeaderFlags.PONG) != 0) {
                pHeader.payloadChecksum += Crypto.Hash32(originalData, 8, 0x14 + (int)(packetReader.BaseStream.Position - readStartPos));
                float LocalTime = packetReader.ReadSingle();
                float HoldingTime = packetReader.ReadSingle();
                result.Add($"PONG({Math.Round(LocalTime,5)} ++ {Math.Round(HoldingTime,5)})");
            }

            if ((header & ACEPacketHeaderFlags.Flow) != 0) {
                pHeader.payloadChecksum += Crypto.Hash32(originalData, 6, 0x14 + (int)(packetReader.BaseStream.Position - readStartPos));
                uint FlowCBDataRecvd = packetReader.ReadUInt32();
                ushort FlowInterval = packetReader.ReadUInt16();
                result.Add($"Flow(rcvd:{FlowCBDataRecvd},int:{FlowInterval})");
            }

            if ((header & ACEPacketHeaderFlags.FRAG) != 0) {
                int pos = (int)(packetReader.BaseStream.Position - readStartPos);
                int len = pHeader.datalen_;
                int bailcounter = 32;
                while (pos < len && bailcounter-- > 0) {
                    int thislen = int.MaxValue;
                    try {
                        thislen = BitConverter.ToUInt16(originalData, pos + 0x1E);
                        pHeader.payloadChecksum += Crypto.Hash32(originalData, thislen, 0x14 + pos);
                    } catch { break; }
                    pos += thislen;
                }
            }
            if ((header & ACEPacketHeaderFlags.EncCRC) != 0) {
                if (isSend && SendCrypto.ContainsKey(pHeader.recID_)) {
                    uint xor = (pHeader.checksum_ - pHeader.headerChecksum) ^ pHeader.payloadChecksum; // nothing to see here, move along.
                    int keyPos = Crypto.ValidateXORCRC(SendCrypto[pHeader.recID_], xor);
                    if (keyPos == -1) result[0] = $"XOR CRC(INVALID)";
                    else result[0] = $"XOR CRC({keyPos})";
                } else if (!isSend && RecvCrypto.ContainsKey(pHeader.recID_)) {
                    uint xor = (pHeader.checksum_ - pHeader.headerChecksum) ^ pHeader.payloadChecksum; // nothing to see here, move along.
                    int keyPos = Crypto.ValidateXORCRC(RecvCrypto[pHeader.recID_], xor);
                    if (keyPos == -1) result[0] = $"XOR CRC(INVALID)";
                    else result[0] = $"XOR CRC({keyPos})";
                } else result.RemoveAt(0);  // result[0] = $"(? XOR CRC)";

            } else {
                if (pHeader.checksum_ != (pHeader.headerChecksum + pHeader.payloadChecksum)) result[0] = $"CRC(INVALID)";
                else result[0] = $"CRC";
            }

            if (result.Count != 0) packetHeadersStr.Append(result.Aggregate((a, b) => a + " | " + b));
            return (int)(packetReader.BaseStream.Position - readStartPos);
        }

    }



}
