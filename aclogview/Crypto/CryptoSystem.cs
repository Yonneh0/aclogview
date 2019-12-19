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
        public List<uint> xors = new List<uint>(256);
        public CryptoSystem() { }
        public CryptoSystem(uint seed, ISAACProvider provider) {
            Init(seed, provider);
        }

        private uint GetKey() {
            return unchecked((uint)isaac.Next());
        }
        public void Eat(uint key) {
            xors.Remove(key);
            xors.Add(GetKey());
            eaten++;
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
            xors = new List<uint>(256);
            for (int i = 0; i < 256; i++) xors.Add(GetKey());
        }

        public void Init(uint seed, ISAACProvider provider) {
            CreateRandomGen(seed, provider);
        }

        public int IndexOf(uint xor) {
            var u = xors.IndexOf(xor);
            if (u > -1) {
                return u + eaten;
            } else {
                return u;
            }
        }
    }
}
