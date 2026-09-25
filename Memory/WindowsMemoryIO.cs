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
        if (length > (ulong)Array.MaxLength)
            throw new ArgumentOutOfRangeException(nameof(length), "Read length exceeds the supported array size.");
        ThrowIfProcessExited();
        var result = new byte[length];

        if (!WindowsPinvoke.ReadProcessMemory(processHandler.Process.Handle, (IntPtr)address, result, new UIntPtr((uint)result.Length), out var bytesRead))
        {
            var errorCode = Marshal.GetLastPInvokeError();
            ThrowIfProcessExited();

            throw new PinvokeException(nameof(WindowsPinvoke.ReadProcessMemory), errorCode);
        }

        if (bytesRead.ToUInt64() != length)
            throw new IncompleteMemoryTransferException("ReadProcessMemory", address, length, bytesRead.ToUInt64());

        return result;
    }

    public void WriteMemory(long address, params byte[] value)
    {
        ArgumentNullException.ThrowIfNull(value);
        ThrowIfProcessExited();

        if (!WindowsPinvoke.WriteProcessMemory(processHandler.Process.Handle, (IntPtr)address, value, new UIntPtr((uint)value.Length), out var bytesWritten))
        {
            var errorCode = Marshal.GetLastPInvokeError();
            ThrowIfProcessExited();

            throw new PinvokeException(nameof(WindowsPinvoke.WriteProcessMemory), errorCode);
        }

        if (bytesWritten.ToUInt64() != (ulong)value.Length)
            throw new IncompleteMemoryTransferException("WriteProcessMemory", address, (ulong)value.Length, bytesWritten.ToUInt64());
    }

    private void ThrowIfProcessExited()
    {
        if (processHandler.Process.HasExited)
            throw new InvalidOperationException("The target process has exited.");
    }
}