using MemoryShark.Memory.Regions;
using MemoryShark.Providers;
using MemoryShark.Windows.Native.Structures;
using MemoryShark.Windows.Providers;

namespace MemoryShark.Windows.Memory.Regions;

public class WindowsMemoryRegionEnumerator : IMemoryRegionEnumerator<MemoryBasicInformation>
{
    private readonly IMemoryRegionInformationProvider<MemoryBasicInformation> memoryRegionInformationProvider;
    private readonly IWindowsSystemInformationProvider systemInformationProvider;

    public WindowsMemoryRegionEnumerator(IMemoryRegionInformationProvider<MemoryBasicInformation> memoryRegionInformationProvider, IWindowsSystemInformationProvider systemInformationProvider)
    {
        this.memoryRegionInformationProvider = memoryRegionInformationProvider ?? throw new ArgumentNullException(nameof(memoryRegionInformationProvider));
        this.systemInformationProvider = systemInformationProvider ?? throw new ArgumentNullException(nameof(systemInformationProvider));
    }

    public IEnumerable<MemoryBasicInformation> EnumerateMemoryRegions()
    {
        var systemInformation = systemInformationProvider.GetSystemInformation();
        MemoryBasicInformation memoryRegion;

        var minimumAddress = systemInformation.MinimumApplicationAddress.ToInt64();
        var maximumAddress = systemInformation.MaximumApplicationAddress.ToInt64();

        for (var currentAddress = minimumAddress; currentAddress < maximumAddress; currentAddress += (long)memoryRegion.RegionSize)
        {
            memoryRegion = memoryRegionInformationProvider.GetRegionInformation(currentAddress);

            yield return memoryRegion;
        }
    }
}