using MemoryShark.Memory;

namespace Sharkbytes.Core
{

    public class WindowsScanner : IScanner
    {
        private readonly IMemoryIO memoryIO;

        public WindowsScanner(IMemoryIO memoryIO)
        {
            this.memoryIO = memoryIO ?? throw new ArgumentNullException(nameof(memoryIO));

        }

        public long[]? Scan(IAlgorithm algorithm, byte?[] signature)
        {
            return null;
        }
    }


}

