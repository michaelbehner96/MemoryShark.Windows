using System.Runtime.InteropServices;
using MemoryShark.Exceptions;
using MemoryShark.Memory.Allocation;
using MemoryShark.Processes;
using MemoryShark.Windows.Native;
using MemoryShark.Windows.Native.Constants;

namespace MemoryShark.Windows.Memory.Allocation;

public class WindowsMemoryDeallocator : IMemoryDeallocator
{
    private readonly IProcessHandler processHandler;

    public WindowsMemoryDeallocator(IProcessHandler processHandler)
    {
        this.processHandler = processHandler ?? throw new ArgumentNullException(nameof(processHandler));
    }

    public void Deallocate(long baseAddress)
    {
        if (!WindowsPinvoke.VirtualFreeEx(processHandler.Process.Handle, (IntPtr)baseAddress, UIntPtr.Zero, AllocationTypeFlags.Release))
            throw new PinvokeException(nameof(WindowsPinvoke.VirtualFreeEx), Marshal.GetLastPInvokeError());
    }
}