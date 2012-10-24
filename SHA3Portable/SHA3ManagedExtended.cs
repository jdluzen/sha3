using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SHA3
{
    public partial class SHA3Managed
    {
        public override int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            if (inputOffset < 0)
                throw new ArgumentOutOfRangeException("inputOffset", "offset out of range");
            if (outputOffset < 0)
                throw new ArgumentOutOfRangeException("outputOffset", "offset out of range");
            HashCore(inputBuffer, inputOffset, inputCount);
            return inputCount;
        }

        public override byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            if (inputOffset < 0)
                throw new ArgumentOutOfRangeException("inputOffset", "offset out of range");
            HashCore(inputBuffer, inputOffset, inputCount);
            HashValue = HashFinal();
            return inputBuffer;
        }
    }
}
