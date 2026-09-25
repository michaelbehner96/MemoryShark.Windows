namespace MemoryShark.Windows.Native.Constants;

/// <summary>Windows system error codes defined by WinError.h.</summary>
public enum WindowsErrorCode : uint
{
    AccessDenied = 5,
    InvalidHandle = 6,
    PartialCopy = 299,
    InvalidAddress = 487,
    NoAccess = 998
}