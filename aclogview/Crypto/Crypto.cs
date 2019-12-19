using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace aclogview {
    public enum ISAACProvider {
        Rand,
        Rand2
    }
    public enum CryptoSystemImplementation {
        CryptoSystem,
        CryptoSystem2
    }
    public interface IISAACProvider {
        void Init(byte[] seed);
        int Next();
        int GetValuesTakenCount();
    }
    public interface ICryptoSystem {
        void Init(uint seed, ISAACProvider provider);
        int IndexOf(uint xor);
        void Eat(uint key);
    }

    public static class Crypto {
        public static int ValidateXORCRC(ICryptoSystem cryptoSystem, uint xor) {
            try {
                int keyPos = cryptoSystem.IndexOf(xor);
                if (keyPos > -1) {
                    cryptoSystem.Eat(xor);
                    return keyPos;
                }
            } catch { }
            return -1;
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
    }
}
