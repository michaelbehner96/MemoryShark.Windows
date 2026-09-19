using MemoryShark.Memory.Regions;
using MemoryShark.Windows.Native;
using MemoryShark.Windows.Native.Structures;

namespace MemoryShark.Windows.Memory.Regions;

public class WindowsMemoryRegionEnumerator : IMemoryRegionEnumerator<MemoryBasicInformation>
{
    private readonly IMemoryRegionAnalyzer<MemoryBasicInformation> memoryRegionAnalyzer;
    private readonly IWindowsSystemInformationProvider systemInformationProvider;

    // Preserve the existing constructor for callers that use the native provider.
    public WindowsMemoryRegionEnumerator(IMemoryRegionAnalyzer<MemoryBasicInformation> memoryRegionAnalyzer)
        : this(memoryRegionAnalyzer, new WindowsSystemInformationProvider())
    {
    }

    public WindowsMemoryRegionEnumerator(IMemoryRegionAnalyzer<MemoryBasicInformation> memoryRegionAnalyzer,
        IWindowsSystemInformationProvider systemInformationProvider)
    {
        this.memoryRegionAnalyzer =
            memoryRegionAnalyzer ?? throw new ArgumentNullException(nameof(memoryRegionAnalyzer));
        this.systemInformationProvider = systemInformationProvider
                                         ?? throw new ArgumentNullException(nameof(systemInformationProvider));
    }

    public IEnumerable<MemoryBasicInformation> EnumerateMemoryRegions()
    {
        var systemInformation = systemInformationProvider.GetSystemInformation();
        var memoryRegion = new MemoryBasicInformation();

        var minimumAddress = systemInformation.MinimumApplicationAddress.ToInt64();
        var maximumAddress = systemInformation.MaximumApplicationAddress.ToInt64();

        for (var currentAddress = minimumAddress;
             currentAddress < maximumAddress;
             currentAddress += (long)memoryRegion.RegionSize)
        {
            memoryRegion = memoryRegionAnalyzer.Analyze(currentAddress);
            yield return memoryRegion;
        }
    }
}