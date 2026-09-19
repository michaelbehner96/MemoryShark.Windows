using System.Runtime.InteropServices;
using MemoryShark.Exceptions;
using MemoryShark.Memory.Regions;
using MemoryShark.Processes;
using MemoryShark.Windows.Native;
using MemoryShark.Windows.Native.Structures;

namespace MemoryShark.Windows.Memory.Regions;

public class WindowsMemoryRegionAnalyzer : IMemoryRegionAnalyzer<MemoryBasicInformation>
{
    private readonly IProcessHandler processHandler;

    public WindowsMemoryRegionAnalyzer(IProcessHandler processHandler)
    {
        this.processHandler = processHandler ?? throw new ArgumentNullException(nameof(processHandler));
    }

    public MemoryBasicInformation Analyze(long address)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Windows memory-region queries are only available on Windows.");

        // The current MemoryBasicInformation interop layout matches the 64-bit native structure.
        // Reject a 32-bit caller before passing that incompatible layout to VirtualQueryEx.
        if (!Environment.Is64BitProcess)
            throw new PlatformNotSupportedException(
                "Memory-region queries require a 64-bit calling process because the current MemoryBasicInformation layout is 64-bit.");

        var virtualQueryWasSuccessful = WindowsPinvoke.VirtualQueryEx(processHandler.Process.Handle, (IntPtr)address,
            out var memInfo, new UIntPtr((uint)Marshal.SizeOf<MemoryBasicInformation>())) != UIntPtr.Zero;

        if (!virtualQueryWasSuccessful)
            throw new PinvokeException(nameof(WindowsPinvoke.VirtualQueryEx), Marshal.GetLastPInvokeError());

        return memInfo;
    }
}