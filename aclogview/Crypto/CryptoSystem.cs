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
        public List<uint> eatenKeys = new List<uint>(); // not needed for server- just for pcap validating local resends
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
                xors.Add(isaac.Next()); // pull next key
                eatenKeys.Add(xor);// not used on server- remove me. Just needed for pcap
                if (eatenKeys.Count > 128) eatenKeys.RemoveRange(0, eatenKeys.Count - 64); // not used on server- remove me. Just needed for pcap
                return ++eaten;
            } else if (eatenKeys.Remove(xor)) {
                eatenKeys.Add(xor);// not used on server- remove me. Just needed for pcap
                // bumping key to bottom of list, so it's not pruned.
                return 1337;
            } else return -1;
        }
    }
}
