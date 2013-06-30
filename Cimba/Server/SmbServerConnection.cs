namespace Cimba.Server
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Net.Sockets;
    using System.Threading;
    using Cimba.Protocol;
    using Cimba.Protocol.External.Microsoft;

    public delegate void ConnectionClosedDelegate();

    public class SmbServerConnection
    {
        private readonly TcpClient tcpClient;

        private readonly NetworkStream stream;

        private bool maintainConnection = true;

        private Thread readerThread;

        private List<ulong> commandSequenceWindow = new List<ulong>(new ulong[] { (ulong)0 });

        private ulong nextMessageSequenceNum = 0;

        private List<Packet> clientRequests = new List<Packet>();

        private List<Packet> asyncCommandList = new List<Packet>();

        private Dictionary<ulong, SmbServerSession> sessions = new Dictionary<ulong, SmbServerSession>();

        internal SmbServerConnection(TcpClient tcpClient)
        {
            this.ClientGuid = new Guid();

            this.tcpClient = tcpClient;
            this.stream = this.tcpClient.GetStream();

            this.Valid = false;

            this.readerThread = new Thread(this.ConnectionReader);
            this.readerThread.Start();

            SpinWait.SpinUntil(() =>
                {
                    return this.clientRequests.Count == 1;
                });

            bool neg_ok = false;
            Packet request = this.clientRequests[0];
            if (request is SmbComNegotiate)
            {
                SmbComNegotiate negrequest = (SmbComNegotiate)request;
                neg_ok = negrequest.Dialects.Contains("SMB 2.002");
            }
            else if (request is NegotiateRequest)
            {
                NegotiateRequest negrequest = (NegotiateRequest)request;
                neg_ok = (new List<ushort>(negrequest.Dialects)).Contains((ushort)Negotiate_Dialects.V20) && (negrequest.MessageId == 0);
            }

            if (neg_ok)
            {
                NegotiateResponse response = new NegotiateResponse();
                response.DialectRevision = (ushort)Negotiate_Dialects.V20;
                response.ServerGuid = SmbServer.Guid;
                response.SecurityBuffer = SPNG.GenerateNegTokenInit2();
                response.SystemTime = DateTime.Now;
                response.SecurityMode = Negotiate_SecurityMode.SigningEnabled;
                response.MaxReadSize = 65536;
                response.MaxWriteSize = 65536;
                response.MaxTransactSize = 65536;

                response.CreditResponse = 1;
                response.CreditCharge = 1;

                byte[] packetstream = response;
                lock (this.stream)
                {
                    this.stream.Write(packetstream, 0, packetstream.Length);
                }

                this.clientRequests.Remove(request);

                this.Valid = true;
            }
            else
            {
                this.maintainConnection = false;
                this.readerThread.Join();
                this.tcpClient.Close();
                this.Valid = false;
                throw new SmbProtocolException("Client did not negotiate correctly");
            }
        }

        public string ClientName { get; private set; }

        public bool RequireSigning { get; private set; }

        public SmbVersion Dialect { get; private set; }

        public bool SupportsMultiCredit { get; private set; }

        public Guid ClientGuid { get; private set; }

        public bool Valid { get; private set; }

        public ConnectionClosedDelegate Closed { private get; set; }

        internal NewSessionDelegate NewSession { get; set; }

        internal AuthenticateClientDelegate AuthenticateClient { get; set; }

        internal void SendPacket(Packet request, Packet response)
        {
            response.MessageId = request.MessageId;
            response.CreditCharge = request.CreditCharge;
            response.CreditResponse = request.CreditRequest;
            response.IsRequest = false;
            byte[] packetstream = response;
            lock (this.stream)
            {
                this.stream.Write(packetstream, 0, packetstream.Length);
            }

            this.clientRequests.Remove(request);
        }

        internal void ClientError(Packet packet, uint code)
        {
            ErrorResponse response = new ErrorResponse(packet);
            response.Status = code;
            this.SendPacket(packet, response);
        }

        internal void Disconnect()
        {
            this.maintainConnection = false;
            this.readerThread.Join();
            this.tcpClient.Close();
            this.Valid = false;
            if (this.Closed != null)
            {
                this.Closed();
            }
        }

        private void ProcessPacket(Packet packet)
        {
            if (packet is NegotiateRequest || packet is SmbComNegotiate)
            {
                return;
            }
            else if (packet is SessionSetupRequest)
            {
                SpinWait.SpinUntil(() =>
                {
                    return this.NewSession != null && this.AuthenticateClient != null;
                });
                if (this.sessions.ContainsKey(packet.SessionId))
                {
                    this.sessions[packet.SessionId].ProcessPacket(packet);
                }
                else
                {
                    try
                    {
                        SmbServerSession newsession = new SmbServerSession(this, packet, this.AuthenticateClient, this.NewSession);
                        this.sessions.Add(newsession.SessionId, newsession);
                    }
                    catch (ArgumentException)
                    {
                        this.ClientError(packet, NTSTATUS.STATUS_INVALID_PARAMETER);
                    }
                }
            }
            else if (packet is LogoffRequest)
            {
                if (this.sessions.ContainsKey(packet.SessionId))
                {
                    this.sessions.Remove(packet.SessionId);
                    LogoffResponse response = new LogoffResponse();
                    response.SessionId = packet.SessionId;
                    this.SendPacket(packet, response);
                }
                else
                {
                    this.ClientError(packet, NTSTATUS.STATUS_USER_SESSION_DELETED);
                }
            }
            else if (packet is QueryInfoRequest)
            {
                this.ClientError(packet, NTSTATUS.STATUS_NOT_SUPPORTED);
            }
            else
            {
                if (this.sessions.ContainsKey(packet.SessionId))
                {
                    this.sessions[packet.SessionId].ProcessPacket(packet);
                }
                else
                {
                    this.ClientError(packet, NTSTATUS.STATUS_USER_SESSION_DELETED);
                }
            }
        }

        private void ConnectionReader()
        {
            NetworkStream stream = this.tcpClient.GetStream();
            byte[] netbios_header = new byte[4];
            byte[] data;
            int datalength;
            while (true)
            {
                SpinWait.SpinUntil(() =>
                    {
                        return !this.maintainConnection || stream.DataAvailable;
                    });

                if (!this.maintainConnection)
                {
                    break;
                }

                netbios_header = Packet.ForceRead(stream, netbios_header, 4);
                datalength = BitConverterBigEndian.ToUShort(netbios_header, 2);
                data = new byte[datalength];
                /*try
                {*/
                data = Packet.ForceRead(stream, data, datalength);
                if (!this.Valid)
                {
                    if (Packet.IsSmb1(data))
                    {
                        Packet smbNeg = Packet.ReadSmbComNegotiate(data);
                        this.clientRequests.Add(smbNeg);
                        continue;
                    }
                }

                Packet[] packets = Packet.Read((this.Dialect == 0 ? SmbVersion.V21 : this.Dialect), this.RequireSigning, new MemoryStream(data, 0, datalength, false, false));
                foreach (Packet packet in packets)
                {
                    this.clientRequests.Add(packet);
                    this.ProcessPacket(packet);
                }

                /*}
                catch (IOException e)
                {
                    if (e is IOException || e is SocketException)
                    {
                        SmbServer.RemoveConnection(this);
                        this.Valid = false;
                        this.maintainConnection = false;
                        this.tcpClient.Close();
                        this.Closed();
                    }
                    else
                    {
                        throw;
                    }
                }*/
            }
        }
    }
}
