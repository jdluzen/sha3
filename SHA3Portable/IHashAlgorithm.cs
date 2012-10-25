using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SHA3
{
    public interface IHashAlgorithm
    {
        int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset);
        byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount);
        void Initialize();
        byte[] Hash { get; }
    }
}
