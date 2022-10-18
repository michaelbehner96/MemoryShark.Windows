using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using MemoryShark.Exceptions;
using MemoryShark.Memory.Allocation;
using MemoryShark.Processes;
using MemoryShark.Windows.Native;
using MemoryShark.Windows.Native.Constants;

namespace MemoryShark.Windows.Memory.Allocation
{
    public class WindowsMemoryAllocator : IMemoryAllocator
    {
        private readonly IProcessHandler processHandler;

        public WindowsMemoryAllocator(IProcessHandler processHandler)
        {
            this.processHandler = processHandler ?? throw new ArgumentNullException(nameof(processHandler));
        }

        public long Allocate(long? address, uint sizeInBytes)
        {
            var allocationBase = WindowsPinvoke.VirtualAllocEx(processHandler.Process.Handle, address.HasValue ? (IntPtr)address : (IntPtr)null, sizeInBytes, AllocationTypeFlags.Commit | AllocationTypeFlags.Reserve, MemoryProtectionFlags.ExecuteReadWrite);

            if (allocationBase == IntPtr.Zero)
                throw new PinvokeException(nameof(WindowsPinvoke.VirtualAllocEx), Marshal.GetLastPInvokeError());

            return (long)allocationBase;
        }
    }
}
