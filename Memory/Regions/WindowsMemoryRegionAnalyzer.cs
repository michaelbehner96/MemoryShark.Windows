using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using MemoryShark.Exceptions;
using MemoryShark.Memory.Regions;
using MemoryShark.Processes;
using MemoryShark.Windows.Native;
using MemoryShark.Windows.Native.Structures;

namespace MemoryShark.Windows.Memory.Regions
{
    public class WindowsMemoryRegionAnalyzer : IMemoryRegionAnalyzer<MemoryBasicInformation>
    {
        private readonly IProcessHandler processHandler;

        public WindowsMemoryRegionAnalyzer(IProcessHandler processHandler)
        {
            this.processHandler = processHandler ?? throw new ArgumentNullException(nameof(processHandler));
        }

        public MemoryBasicInformation Analyze(long address)
        {
            var virtualQueryWasSuccessful = WindowsPinvoke.VirtualQueryEx(processHandler.Process.Handle, (IntPtr)address, out MemoryBasicInformation memInfo, (uint)Marshal.SizeOf<MemoryBasicInformation>()) != 0;

            if (!virtualQueryWasSuccessful)
                throw new PinvokeException(nameof(WindowsPinvoke.VirtualQueryEx), Marshal.GetLastPInvokeError());

            return memInfo;
        }
    }
}
