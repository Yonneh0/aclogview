using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace aclogview {
    public class CryptoSystem : ICryptoSystem {
        private uint seed;
        private int eaten;
        public IISAACProvider isaac;
        public HashSet<uint> xors = new HashSet<uint>();
        public CryptoSystem() { }
        public CryptoSystem(uint seed, ISAACProvider provider) {
            Init(seed, provider);
        }

        private void CreateRandomGen(uint seed, ISAACProvider provider) {
            this.seed = seed;
            int signed_seed = unchecked((int)seed);

            switch (provider) {
                case ISAACProvider.Rand:
                    isaac = new Rand();
                    isaac.Init(BitConverter.GetBytes(signed_seed));
                    break;
                case ISAACProvider.Rand2:
                    isaac = new Rand2();
                    isaac.Init(BitConverter.GetBytes(signed_seed));
                    break;
            }
            xors.Clear();
            for (int i = 0; i < 256; i++) xors.Add(isaac.Next());
        }

        public void Init(uint seed, ISAACProvider provider) {
            CreateRandomGen(seed, provider);
        }

        public int ConsumeKey(uint xor) {
            if (xors.Remove(xor)) {
                xors.Add(isaac.Next());
                return ++eaten;
            } else return -1;
        }
    }
}
