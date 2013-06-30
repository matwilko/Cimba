namespace Cimba.Server
{
    using System;
    using System.Net;
    using System.Net.Sockets;
    using System.Threading;

    public delegate Tuple<NewSessionDelegate, AuthenticateClientDelegate> NewConnectionDelegate(SmbServerConnection connection);

    public static class SmbServer
    {
        internal static readonly DateTime StartTime = DateTime.Now;

        internal static readonly Guid Guid = Guid.NewGuid();

        private static Thread listenerThread;

        private static TcpListener tcpListener;

        private static NewConnectionDelegate handler;

        public static bool ServerEnabled { get; private set; }

        public static string ServerName { get; private set; }

        public static void Listen(IPEndPoint localEP, NewConnectionDelegate handler, string serverName, bool requireSigning = false)
        {
            if (SmbServer.tcpListener != null)
            {
                throw new SmbConnectionException("Already listening for connections. You must stop listening on the current binding before listening on another.");
            }

            SmbServer.ServerName = serverName;

            SmbServer.tcpListener = new TcpListener(localEP);
            SmbServer.Listen(handler);
        }

        public static void Listen(IPAddress ip, NewConnectionDelegate handler, string serverName, int port = 445, bool requireSigning = false)
        {
            if (SmbServer.tcpListener != null)
            {
                throw new SmbConnectionException("Already listening for connections. You must stop listening on the current binding before listening on another.");
            }

            SmbServer.ServerName = serverName;

            SmbServer.tcpListener = new TcpListener(ip, port);
            SmbServer.Listen(handler);
        }

        public static void Listen(string hostName, NewConnectionDelegate handler, string serverName, int port = 445, bool requireSigning = false)
        {
            if (SmbServer.tcpListener != null)
            {
                throw new SmbConnectionException("Already listening for connections. You must stop listening on the current binding before listening on another.");
            }

            SmbServer.ServerName = serverName;

            IPAddress[] addresses = Dns.GetHostAddresses(hostName);
            for (int i = 0; i < addresses.Length; i++)
            {
                try
                {
                    SmbServer.tcpListener = new TcpListener(addresses[i], port);
                    SmbServer.Listen(handler);
                    return;
                }
                catch (SocketException)
                {
                    continue;
                }
            }

            throw new SmbConnectionException("Could not bind on the specified host name");
        }

        public static void Disable()
        {
            SmbServer.ServerEnabled = false;
            SmbServer.listenerThread.Join();

            // TODO: Close all connections
            SmbServer.handler = null;
            SmbServer.tcpListener = null;
            SmbServer.listenerThread = null;
        }

        public static long NextInt64(this Random rnd)
        {
            var buffer = new byte[sizeof(long)];
            rnd.NextBytes(buffer);
            return BitConverter.ToInt64(buffer, 0);
        }

        internal static void RemoveConnection(SmbServerConnection conn)
        {
        }

        private static void Listen(NewConnectionDelegate handler)
        {
            SmbServer.ServerEnabled = true;
            SmbServer.handler = handler;

            SmbServer.listenerThread = new Thread(SmbServer.ConnectionListener);
            SmbServer.listenerThread.Start();
        }

        private static void ConnectionListener()
        {
            SmbServer.tcpListener.Start();
            while (true)
            {
                SpinWait.SpinUntil(() =>
                    {
                        return !SmbServer.ServerEnabled || SmbServer.tcpListener.Pending();
                    });

                if (!SmbServer.ServerEnabled)
                {
                    break;
                }

                Console.WriteLine("NEW CONNECTION");

                // There is now a connection to listen to
                SmbServerConnection conn = new SmbServerConnection(SmbServer.tcpListener.AcceptTcpClient());

                // TODO: Maintain a list of active connections
                Tuple<NewSessionDelegate, AuthenticateClientDelegate> delegates = SmbServer.handler(conn);
                conn.NewSession = delegates.Item1;
                conn.AuthenticateClient = delegates.Item2;
            }

            SmbServer.tcpListener.Stop();
        }
    }
}
