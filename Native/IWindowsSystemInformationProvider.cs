using MemoryShark.Windows.Native.Structures;

namespace MemoryShark.Windows.Native;

public interface IWindowsSystemInformationProvider
{
    SystemInformation GetSystemInformation();
}