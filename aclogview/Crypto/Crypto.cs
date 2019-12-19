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
        uint Next();
        int GetValuesTakenCount();
    }
    public interface ICryptoSystem {
        void Init(uint seed, ISAACProvider provider);
        int ConsumeKey(uint xor);
    }

    public static class Crypto {
        public static int ValidateXORCRC(ICryptoSystem cryptoSystem, uint xor) {
            try {
                return cryptoSystem.ConsumeKey(xor);
            } catch { return -1; }
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
    }
}
