using MemoryShark.Exceptions;
using MemoryShark.Memory.Allocation;
using MemoryShark.Processes;
using MemoryShark.Windows.Native;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace MemoryShark.Windows.Memory.Allocation
{
    public class WindowsMemoryDeallocator : IMemoryDeallocator
    {
        private readonly IProcessHandler processHandler;

        public WindowsMemoryDeallocator(IProcessHandler processHandler)
        {
            this.processHandler = processHandler ?? throw new ArgumentNullException(nameof(processHandler));
        }

        public void Deallocate(long baseAddress)
        {
            if (!WindowsPinvoke.VirtualFreeEx(processHandler.Process.Handle, (IntPtr)baseAddress, 0, Native.Constants.AllocationTypeFlags.Release))
                throw new PinvokeException(nameof(WindowsPinvoke.VirtualFreeEx), Marshal.GetLastPInvokeError());
        }
    }
}
