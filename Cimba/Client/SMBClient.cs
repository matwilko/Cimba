namespace Cimba.Client
{
    using System;
    using System.Collections.Generic;
    using System.Net;
    using System.Net.Sockets;

    /// <summary>
    /// Globally represents the client side of the SMB2 protocol. Used to initiate connections to servers.
    /// </summary>
    /// <example>
    /// <code>SmbClientConnection conn = SmbClient.Connect("WINDOWSSERVER");</code>
    /// </example>
    public static class SmbClient
    {
        /// <summary>
        /// The ClientGuid of the SMB2 Client.
        /// [SMB2-3.2.1.1]
        /// </summary>
        internal static readonly Guid ClientGuid = Guid.NewGuid();

        /// <summary>
        /// A table of active connections.
        /// [SMB2-3.2.1.1]
        /// </summary>
        /// <see cref="SmbClientConnection"/>
        private static Dictionary<IPEndPoint, SmbClientConnection> connectionTable = new Dictionary<IPEndPoint, SmbClientConnection>(new IPEndPointComparer());

        /// <summary>
        /// A table of opened files, indexed by name.
        /// [SMB2-3.2.1.1]
        /// </summary>
        /// <see cref="SmbClientOpen"/>
        private static Dictionary<string, SmbClientFile> globalFileTableByFileName = new Dictionary<string, SmbClientFile>();

        /// <summary>
        /// A table of opened files, indexed by LeaseKey.
        /// </summary>
        /// <see cref="SmbClientOpen"/>
        private static Dictionary<Guid, SmbClientFile> globalFileTableByLeaseKey = new Dictionary<Guid, SmbClientFile>();

        /// <summary>
        /// The time the SMB2 Client started.
        /// </summary>
        private static DateTime clientStartTime = DateTime.Now;

        /// <summary>
        /// Attempt to connect to the specified remote IP End Point, and negotiate the SMB2 protocol with it.
        /// If a connection to the specified End Point already exists, this will be returned.
        /// </summary>
        /// <param name="remoteEP">The IP End Point to attempt to connect to.</param>
        /// <param name="requireMessageSigning">Whether or not to require both the Client and Server to sign all messages (where possible)</param>
        /// <returns>An SMBClientConnection object representing the connection.</returns>
        /// <exception cref="SmbConnectionException">Thrown when the IP End Point could not be connected to.</exception>
        /// <exception cref="SmbConnectionException">Thrown when negotiation with the remote server fails.</exception>
        public static SmbClientConnection Connect(IPEndPoint remoteEP, bool requireMessageSigning = true)
        {
            return Connect(remoteEP, remoteEP.ToString(), requireMessageSigning);
        }

        /// <summary>
        /// Attempt to connect to the specified IP Address, and negotiate the SMB2 protocol with it.
        /// If a connection to the specified IP already exists, this will be returned.
        /// </summary>
        /// <param name="ip">The IP address to attempt to connect to.</param>
        /// <param name="port">The port to connect to. Defaults to 445, the SMB2 assigned port.</param>
        /// <param name="requireMessageSigning">Whether or not to require both the Client and Server to sign all messages (where possible)</param>
        /// <returns>An SMBClientConnection object representing the connection.</returns>
        /// <exception cref="SmbConnectionException">Thrown when the IP Address could not be connected to.</exception>
        /// <exception cref="SmbConnectionException">Thrown when negotiation with the remote server fails.</exception>
        public static SmbClientConnection Connect(IPAddress ip, int port = 445, bool requireMessageSigning = true)
        {
            IPEndPoint remoteEP = new IPEndPoint(ip, port);
            return Connect(remoteEP, requireMessageSigning);
        }

        /// <summary>
        /// Attempt to connect to the specified IP Addresses, in order, and negotiate the SMB2 protocol with the first successfully connected to.
        /// If a connection to one of the specified IP Addresses already exists, this will be returned.
        /// </summary>
        /// <param name="ips">The IP addresses to attempt to connect to.</param>
        /// <param name="port">The port to connect to. Defaults to 445, the SMB2 assigned port.</param>
        /// <param name="requireMessageSigning">Whether or not to require both the Client and Server to sign all messages (where possible)</param>
        /// <returns>An SMBClientConnection object representing the connection.</returns>
        /// <exception cref="SmbConnectionException">Thrown when none of the IP Addresses could not be connected to.</exception>
        /// <exception cref="SmbConnectionException">Thrown when negotiation with the remote server fails.</exception>
        public static SmbClientConnection Connect(IPAddress[] ips, int port = 445, bool requireMessageSigning = true)
        {
            for (int i = 0; i < ips.Length; i++)
            {
                if (HaveCurrentConnection(ips[i], port))
                {
                    return Connect(new IPEndPoint(ips[i], port), requireMessageSigning);
                }
            }

            for (int i = 0; i < ips.Length; i++)
            {
                SmbClientConnection conn;
                try
                {
                    conn = Connect(ips[i], port, requireMessageSigning);
                    return conn;
                }
                catch (SocketException)
                {
                    continue;
                }
            }

            throw new SmbConnectionException("Could not connect to any of the specified IP Addresses");
        }

        /// <summary>
        /// Attempt to connect to the specified Host, and negotiate the SMB2 protocol with it.
        /// If a connection to the specified Host already exists, this will be returned.
        /// </summary>
        /// <param name="hostname">The Host to attempt to connect to.</param>
        /// <param name="port">The port to connect to. Defaults to 445, the SMB2 assigned port.</param>
        /// <param name="requireMessageSigning">Whether or not to require both the Client and Server to sign all messages (where possible)</param>
        /// <returns>An SMBClientConnection object representing the connection.</returns>
        /// <exception cref="SmbConnectionException">Thrown when the Host could not be connected to.</exception>
        /// <exception cref="SmbConnectionException">Thrown when negotiation with the remote server fails.</exception>
        public static SmbClientConnection Connect(string hostname, int port = 445, bool requireMessageSigning = true)
        {
            IPAddress[] ips = Dns.GetHostAddresses(hostname);
            for (int i = 0; i < ips.Length; i++)
            {
                if (HaveCurrentConnection(ips[i], port))
                {
                    return Connect(new IPEndPoint(ips[i], port), hostname, requireMessageSigning);
                }
            }

            for (int i = 0; i < ips.Length; i++)
            {
                SmbClientConnection conn;
                try
                {
                    conn = Connect(new IPEndPoint(ips[i], port), hostname, requireMessageSigning);
                    return conn;
                }
                catch (SocketException)
                {
                    continue;
                }
            }

            throw new SmbConnectionException("Could not connect to the specified hostname");
        }

        /// <summary>
        /// Checks whether or not a connection already exists to the specified IP End Point.
        /// </summary>
        /// <param name="remoteEP">The IP End Point to check for a connection to.</param>
        /// <returns>The result of the check. If true, a connection already exists to the specified IP End Point.</returns>
        public static bool HaveCurrentConnection(IPEndPoint remoteEP)
        {
            return connectionTable.ContainsKey(remoteEP);
        }

        /// <summary>
        /// Checks whether or not a connection already exists to the specified IP Address.
        /// </summary>
        /// <param name="ip">The IP Address to check for a connection to.</param>
        /// <param name="port">The port to check for a connection to.</param>
        /// <returns>The result of the check. If true, a connection already exists to the specified IP Address.</returns>
        public static bool HaveCurrentConnection(IPAddress ip, int port = 445)
        {
            return connectionTable.ContainsKey(new IPEndPoint(ip, port));
        }

        /// <summary>
        /// Checks whether or not a connection already exists to the specified Host.
        /// </summary>
        /// <param name="hostname">The Host to check for a connection to.</param>
        /// <param name="port">The port to check for a connection to.</param>
        /// <returns>The result of the check. If true, a connection already exists to the specified Host.</returns>
        public static bool HaveCurrentConnection(string hostname, int port = 445)
        {
            IPAddress[] ips = Dns.GetHostAddresses(hostname);
            for (int i = 0; i < ips.Length; i++)
            {
                if (HaveCurrentConnection(ips[i], port))
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Attempt to connect to the specified remote IP End Point, and negotiate the SMB2 protocol with it.
        /// If a connection to the specified End Point already exists, this will be returned.
        /// </summary>
        /// <param name="remoteEP">The IP End Point to attempt to connect to.</param>
        /// <param name="requireMessageSigning">Whether or not to require both the Client and Server to sign all messages (where possible)</param>
        /// <returns>An SMBClientConnection object representing the connection.</returns>
        /// <exception cref="SmbConnectionException">Thrown when the IP End Point could not be connected to.</exception>
        /// <exception cref="SmbConnectionException">Thrown when negotiation with the remote server fails.</exception>
        private static SmbClientConnection Connect(IPEndPoint remoteEP, string serverName, bool requireMessageSigning = true)
        {
            if (HaveCurrentConnection(remoteEP))
            {
                return SmbClient.connectionTable[remoteEP];
            }
            else
            {
                try
                {
                    TcpClient client = new TcpClient();
                    client.Connect(remoteEP);
                    SmbClientConnection scc = new SmbClientConnection(client, serverName, requireMessageSigning);
                    SmbClient.connectionTable.Add((IPEndPoint)client.Client.RemoteEndPoint, scc);
                    return scc;
                }
                catch (SocketException e)
                {
                    throw new SmbConnectionException("Could not connect to the specified IP Endpoint", e);
                }
            }
        }
    }
}
