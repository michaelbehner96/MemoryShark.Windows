using System.Runtime.InteropServices;
using MemoryShark.Exceptions;
using MemoryShark.Memory;
using MemoryShark.Processes;
using MemoryShark.Windows.Native;

namespace MemoryShark.Windows.Memory;

public class WindowsMemoryIO : IMemoryIO
{
    private readonly IProcessHandler processHandler;

    public WindowsMemoryIO(IProcessHandler processHandler)
    {
        this.processHandler = processHandler ?? throw new ArgumentNullException(nameof(processHandler));
    }

    public byte[] ReadMemory(long address, ulong length)
    {
        var result = new byte[length];
        if (!WindowsPinvoke.ReadProcessMemory(processHandler.Process.Handle, (IntPtr)address, result,
                new UIntPtr((uint)result.Length), out var nullptr))
            throw new PinvokeException(nameof(WindowsPinvoke.ReadProcessMemory), Marshal.GetLastPInvokeError());
        return result;
    }

    public void WriteMemory(long address, params byte[] value)
    {
        if (!WindowsPinvoke.WriteProcessMemory(processHandler.Process.Handle, (IntPtr)address, value,
                new UIntPtr((uint)value.Length), out var nullptr))
            throw new PinvokeException(nameof(WindowsPinvoke.WriteProcessMemory), Marshal.GetLastPInvokeError());
    }
}