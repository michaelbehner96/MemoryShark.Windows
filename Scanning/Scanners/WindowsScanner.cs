using MemoryShark.Memory;
using MemoryShark.Processes;
using MemoryShark.Windows.Native;
using Sharkbytes.Core;
using System.Runtime.InteropServices;
using static MemoryShark.Windows.Native.WindowsPinvoke;

namespace MemoryShark.Windows.Scanning.Scanners
{

    public class WindowsScanner : IScanner
    {
        private readonly IMemoryIO memoryIO;
        private readonly IProcessHandler processHandler;

        public WindowsScanner(IMemoryIO memoryIO, IProcessHandler processHandler)
        {
            this.memoryIO = memoryIO ?? throw new ArgumentNullException(nameof(memoryIO));
            this.processHandler = processHandler ?? throw new ArgumentNullException(nameof(processHandler));

        }

        public long[]? Scan(IAlgorithm algorithm, byte?[] signature)
        {
            // Setup Native Structs and boilerplate code
            SYSTEM_INFO sysInfo = new SYSTEM_INFO();
            MEMORY_BASIC_INFORMATION64 memInfo = new MEMORY_BASIC_INFORMATION64();
            WindowsPinvoke.GetSystemInfo(ref sysInfo);
            List<long> matchedAddresses = new List<long>();

            // From the system info, assert a min/max app memory range
            long minAddress = (long)sysInfo.lpMinimumApplicationAddress;
            long maxAddress = (long)sysInfo.lpMaximumApplicationAddress;

            // Start from bottom
            long currentAddress = minAddress;

            // While we're still less than the max address
            // And our query does not return 0 (aka we're still within application memory as a whole)
            while (currentAddress < maxAddress && 
                WindowsPinvoke.VirtualQueryEx(
                    processHandler.Process.Handle,
                    (IntPtr)currentAddress,
                    out memInfo,
                    (uint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION64>()) != 0)
            {

                // If the state of the memory is COMMIT
                // And the region size is larger than the signature's length
                // ANd the protection level is either E/R/W or R/W
                if (memInfo.State == (int)WindowsPinvoke.AllocationType.Commit 
                    && (long)memInfo.RegionSize > signature.Length 
                    && (memInfo.Protect == (int)WindowsPinvoke.MemoryProtection.ExecuteReadWrite 
                    || memInfo.Protect == (int)WindowsPinvoke.MemoryProtection.ReadWrite))
                {

                    // Read the region into a buffer
                    byte[] bytesRead = memoryIO.ReadMemory((long)memInfo.BaseAddress, (int)memInfo.RegionSize);
                    
                    // Pass that buffer into the algorithm for pattern matching
                    var matches = algorithm.FindMatches(bytesRead, signature);

                    // IF algorithm returns null it means there were no matches
                    if (matches == null)
                        continue;

                    // If there were matches, merge them with the current list of matches
                    foreach (var index in matches)
                    {
                        matchedAddresses.Add((long)memInfo.BaseAddress + index);
                    }
                }

                // Increment our current address to be at the end of the region
                currentAddress += (long)memInfo.RegionSize;
            }

            return matchedAddresses.ToArray();
        }
    }


}

