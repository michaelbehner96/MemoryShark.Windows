using MemoryShark.Windows.Native.Structures;

namespace MemoryShark.Windows.Providers;

public interface IWindowsSystemInformationProvider
{
    SystemInformation GetSystemInformation();
}