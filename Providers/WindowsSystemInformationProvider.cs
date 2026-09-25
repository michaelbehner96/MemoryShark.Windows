using MemoryShark.Windows.Native;
using MemoryShark.Windows.Native.Structures;

namespace MemoryShark.Windows.Providers;

public class WindowsSystemInformationProvider : IWindowsSystemInformationProvider
{
    public SystemInformation GetSystemInformation()
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Windows system information is only available on Windows.");

        var systemInformation = new SystemInformation();
        WindowsPinvoke.GetSystemInfo(ref systemInformation);

        return systemInformation;
    }
}