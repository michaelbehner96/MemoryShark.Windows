using MemoryShark.Processes;
using MemoryShark.Windows.Native.Constants;
using MemoryShark.Windows.Native.Structures;
using MemoryShark.Windows.Native;
using System.Runtime.InteropServices;
using MemoryShark.Memory.Regions;

namespace MemoryShark.Windows.Memory.Regions
{
    public class WindowsMemoryRegionEnumerator : IMemoryRegionEnumerator<MemoryBasicInformation>
    {
        private readonly IMemoryRegionAnalyzer<MemoryBasicInformation> memoryRegionAnalyzer;

        public WindowsMemoryRegionEnumerator(IMemoryRegionAnalyzer<MemoryBasicInformation> memoryRegionAnalyzer)
        {
            this.memoryRegionAnalyzer = memoryRegionAnalyzer ?? throw new ArgumentNullException(nameof(memoryRegionAnalyzer));
        }

        public IEnumerable<MemoryBasicInformation> EnumerateMemoryRegions()
        {
            var sysInfo = new SystemInformation();
            var memInfo = new MemoryBasicInformation();
            WindowsPinvoke.GetSystemInfo(ref sysInfo);

            var minAddress = (long)sysInfo.MinimumApplicationAddress;
            var maxAddress = (long)sysInfo.MaximumApplicationAddress;

            for (var currentAddress = minAddress; currentAddress < maxAddress; currentAddress += (long)memInfo.RegionSize)
            {
                memInfo = memoryRegionAnalyzer.Analyze(currentAddress);
                yield return memInfo;
            }
        }
    }
}
