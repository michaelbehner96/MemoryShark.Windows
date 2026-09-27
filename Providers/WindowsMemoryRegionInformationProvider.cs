using System.Runtime.InteropServices;
using MemoryShark.Exceptions;
using MemoryShark.Processes;
using MemoryShark.Providers;
using MemoryShark.Windows.Native;
using MemoryShark.Windows.Native.Structures;

namespace MemoryShark.Windows.Providers;

public class WindowsMemoryRegionInformationProvider : IMemoryRegionInformationProvider<MemoryBasicInformation>
{
    private readonly IProcessHandler processHandler;

    public WindowsMemoryRegionInformationProvider(IProcessHandler processHandler)
    {
        this.processHandler = processHandler ?? throw new ArgumentNullException(nameof(processHandler));
    }

    public MemoryBasicInformation GetRegionInformation(long address)
    {
        if (address < 0) throw new ArgumentOutOfRangeException(nameof(address));

        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Windows memory-region queries are only available on Windows.");

        if (!Environment.Is64BitProcess)
            throw new PlatformNotSupportedException("Memory-region queries require a 64-bit calling process because the current MemoryBasicInformation layout is 64-bit.");

        var expectedInformationSize = (uint)Marshal.SizeOf<MemoryBasicInformation>();
        var returnedInformationSize = WindowsPinvoke.VirtualQueryEx(processHandler.Process.Handle, (IntPtr)address, out var memInfo, new UIntPtr(expectedInformationSize));

        if (returnedInformationSize == UIntPtr.Zero)
            throw new PinvokeException(nameof(WindowsPinvoke.VirtualQueryEx), Marshal.GetLastPInvokeError());

        if (returnedInformationSize.ToUInt64() != expectedInformationSize)
            throw new InvalidOperationException($"VirtualQueryEx returned {returnedInformationSize.ToUInt64()} bytes; expected {expectedInformationSize} for MemoryBasicInformation.");

        return memInfo;
    }
}