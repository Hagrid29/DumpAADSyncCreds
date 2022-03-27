using System;
using System.Runtime.InteropServices;
using System.Runtime.ConstrainedExecution;
using System.Security;


namespace DumpAADSyncCreds
{
    public class WinAPI
    {
		[DllImport("kernel32.dll", SetLastError = true)]
		[return: MarshalAs(UnmanagedType.Bool)]
		internal static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

		[DllImport("advapi32.dll", SetLastError = true)]
		internal static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, ref Program.LUID lpLuid);

		[DllImport("advapi32.dll", SetLastError = true)]
		[return: MarshalAs(UnmanagedType.Bool)]
		internal static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, [MarshalAs(UnmanagedType.Bool)] bool DisableAllPrivileges, ref Program.TOKEN_PRIVILEGES NewState, uint Zero, IntPtr Null1, IntPtr Null2);

		[ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
		[SuppressUnmanagedCodeSecurity]
		[DllImport("kernel32.dll", SetLastError = true)]
		[return: MarshalAs(UnmanagedType.Bool)]
		internal static extern bool CloseHandle(IntPtr hObject);

		[DllImport("advapi32.dll", SetLastError = true)]
		internal static extern bool DuplicateToken(IntPtr ExistingTokenHandle, int SECURITY_IMPERSONATION_LEVEL, out IntPtr DuplicateTokenHandle);

		[DllImport("advapi32.dll", SetLastError = true)]
		[return: MarshalAs(UnmanagedType.Bool)]
		internal static extern bool SetThreadToken(IntPtr PHThread, IntPtr Token);

		[DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		[return: MarshalAs(UnmanagedType.Bool)]
		internal static extern bool CryptAcquireContext(ref IntPtr hProv, string pszContainer, string pszProvider, uint dwProvType, uint dwFlags);

		[DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		internal static extern bool CryptCreateHash(IntPtr hProv, uint algId, IntPtr hKey, uint dwFlags, ref IntPtr phHash);

		[DllImport("advapi32.dll", SetLastError = true)]
		internal static extern bool CryptHashData(IntPtr hHash, byte[] pbData, uint dataLen, uint flags);

		[DllImport("advapi32.dll", SetLastError = true)]
		internal static extern bool CryptGetHashParam(IntPtr hHash, uint dwParam, byte[] pbData, ref uint dwDataLen, uint dwFlags);

		[DllImport("advapi32.dll", SetLastError = true)]
		internal static extern bool CryptDestroyHash(IntPtr hHash);

		[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		internal static extern bool CryptReleaseContext(IntPtr hProv, int dwFlags);



	}
}
