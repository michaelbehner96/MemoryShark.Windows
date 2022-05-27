using MemoryShark.Memory;
using MemoryShark.Processes;
using MemoryShark.Windows.Native;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MemoryShark.Windows.Memory
{
    public class WindowsMemoryIO : IMemoryIO
    {
        private readonly IProcessHandler processHandler;

        public WindowsMemoryIO(IProcessHandler processHandler)
        {
            this.processHandler = processHandler ?? throw new ArgumentNullException(nameof(processHandler));
        }

        public byte[] ReadMemory(long address, int length)
        {
            byte[] result = new byte[length];
            if (!WindowsPinvoke.ReadProcessMemory(processHandler.Process.Handle, (IntPtr)address, result, result.Length, out var nullptr))
                throw new Exception($"Native {nameof(WindowsPinvoke.ReadProcessMemory)} failed.");
            return result;
        }

        public void WriteMemory(long address, byte[] value)
        {
            if (!WindowsPinvoke.WriteProcessMemory(processHandler.Process.Handle, (IntPtr)address, value, value.Length, out var nullptr))
                throw new Exception($"Native {nameof(WindowsPinvoke.WriteProcessMemory)} failed.");
        }
    }
}
