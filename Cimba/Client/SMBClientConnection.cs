namespace Cimba.Client
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Net.Sockets;
    using System.Threading;
    using Cimba.Protocol;

    public class SmbClientConnection
    {
        private readonly NetworkStream stream;

        private readonly Thread readThread;

        private readonly Dictionary<ulong, Packet> receivedPackets = new Dictionary<ulong, Packet>();

        private TcpClient tcpClient;

        private Dictionary<ulong, SmbClientSession> sessionTableById = new Dictionary<ulong, SmbClientSession>();

        private Dictionary<SmbClientCredentials, SmbClientSession> sessionTableByCredential = new Dictionary<SmbClientCredentials, SmbClientSession>();

        //// OutstandingRequests - table of async requests awaiting response - lookup by CancelId or MessageId

        private Dictionary<ulong, Packet> syncRequests = new Dictionary<ulong, Packet>();

        private ulong largestsequencenum = 0;

        private Dictionary<string, SmbClientOpen> openTableByFileName = new Dictionary<string, SmbClientOpen>();

        private Dictionary<FILE_ID, SmbClientOpen> openTableByFileId = new Dictionary<FILE_ID, SmbClientOpen>();

        private Dictionary<string, SmbClientFile> globalFileTable = new Dictionary<string, SmbClientFile>();

        private byte[] gssNegotiateToken;

        private bool maintainConnection = true;

        private List<ulong> sequenceWindow = new List<ulong>(new ulong[] { 0 });

        internal SmbClientConnection(TcpClient client, string serverName, bool requireMessageSigning)
        {
            this.tcpClient = client;
            this.RequireSigning = requireMessageSigning;
            this.stream = this.tcpClient.GetStream();
            this.Valid = true;

            // TODO: Spin off TCP Connection into separate thread (maintain single thread for each connection)
            this.readThread = new Thread(this.ConnectionReader);
            this.readThread.Start();

            NegotiateRequest out_neg = new NegotiateRequest(requireMessageSigning)
            {
                ASync = false
            };
            NegotiateResponse in_neg = (NegotiateResponse)this.ReceivePacket(this.SendPacket(out_neg));

            this.MaxTransactSize = in_neg.MaxTransactSize;
            this.MaxReadSize = in_neg.MaxReadSize;
            this.MaxWriteSize = in_neg.MaxWriteSize;
            this.ServerGuid = in_neg.ServerGuid;
            this.RequireSigning = in_neg.SecurityMode.HasFlag(Negotiate_SecurityMode.SigningRequired) || this.RequireSigning;
            this.ServerName = serverName;
            this.Dialect = in_neg.DialectRevision == 0x0202 ? SmbVersion.V20 : SmbVersion.V21;
            this.SupportsLeasing = in_neg.Capabilities.HasFlag(NegotiateResponse.Caps.GLOBAL_CAP_LEASING);
            this.SupportsMultiCredit = in_neg.Capabilities.HasFlag(NegotiateResponse.Caps.GLOBAL_CAP_LARGE_MTU);
            this.SupportsDFS = in_neg.Capabilities.HasFlag(NegotiateResponse.Caps.GLOBAL_CAP_DFS);
            this.gssNegotiateToken = in_neg.SecurityBuffer;
        }

        internal delegate Packet AsyncDelegate(ulong MessageId);

        public bool Valid { get; private set; }

        public bool RequireSigning { get; private set; }

        public string ServerName { get; private set; }

        public bool SupportsLeasing { get; private set; }

        public bool SupportsMultiCredit { get; private set; }

        public bool SupportsDFS { get; private set; }

        internal uint MaxTransactSize { get; private set; } // Max buffer size that server will accept

        internal uint MaxReadSize { get; private set; } // Max read size in a READ request

        internal uint MaxWriteSize { get; private set; } // Max write size in a WRITE request

        internal Guid ServerGuid { get; private set; }

        internal SmbVersion Dialect { get; private set; }

        public SmbClientSession SetupSession(SmbClientCredentials creds)
        {
            // TODO: Lookup in SessionTable to ascertain whether there is already a valid session for these NC's
            byte[] newGSS = new byte[this.gssNegotiateToken.Length];
            this.gssNegotiateToken.CopyTo(newGSS, 0);
            return new SmbClientSession(this, creds, newGSS);
        }

        public void Disconnect()
        {
            List<SmbClientSession> sessionlist = new List<SmbClientSession>(this.sessionTableById.Values);
            foreach (SmbClientSession session in sessionlist)
            {
                session.Logoff();
            }

            this.maintainConnection = false;
            this.Valid = false;
            this.readThread.Join();
            this.tcpClient.Close();
        }

        internal ulong SendPacket(Packet packet)
        {
            // TODO: Introduce sequence numbers
            packet.MessageId = this.AllocateMessageId();
            packet.CreditCharge = 1;
            packet.CreditRequest = 2;
            byte[] packetstream = packet;
            this.stream.Write(packetstream, 0, packetstream.Length);
            this.syncRequests.Add(packet.MessageId, packet);
            return packet.MessageId;
        }

        internal Packet ReceivePacket(ulong messageId)
        {
            SpinWait.SpinUntil(() =>
                {
                    return this.receivedPackets.ContainsKey(messageId);
                });

            Packet packet = this.receivedPackets[messageId];
            this.receivedPackets.Remove(messageId);
            return packet;
        }

        internal void AddOpen(SmbClientOpen open)
        {
            this.openTableByFileName.Add(open.FileName, open);
            this.openTableByFileId.Add(open.FileId, open);
            if (this.SupportsLeasing && this.Dialect == SmbVersion.V21)
            {
                if (this.globalFileTable.ContainsKey(open.FileName))
                {
                    this.globalFileTable[open.FileName].AddOpen(open);
                }
                else
                {
                    SmbClientFile file = new SmbClientFile(open);
                    this.globalFileTable.Add(open.FileName, file);
                }
            }
        }

        internal void RemoveOpen(SmbClientOpen open)
        {
            this.openTableByFileId.Remove(open.FileId);
            this.openTableByFileName.Remove(open.FileName);
            if (this.SupportsLeasing && this.Dialect == SmbVersion.V21)
            {
                this.globalFileTable[open.FileName].RemoveOpen(open);
            }
        }

        internal void RemoveFile(SmbClientFile file)
        {
            this.globalFileTable.Remove(file.FileName);
        }

        internal void RemoveOpenByTreeConnect(SmbClientTreeConnect treeConnect)
        {
            List<SmbClientOpen> openlist = new List<SmbClientOpen>(this.openTableByFileId.Values);
            for (int i = 0; i < openlist.Count; i++)
            {
                SmbClientOpen open = openlist[i];

                if (open.TreeConnect == treeConnect)
                {
                    open.Close();
                }
            }
        }

        internal void RemoveSession(SmbClientCredentials cred, ulong sessionId)
        {
            this.sessionTableByCredential.Remove(cred);
            this.sessionTableById.Remove(sessionId);
        }

        private ulong AllocateMessageId()
        {
            ulong id;
            lock (this.sequenceWindow)
            {
                id = this.sequenceWindow[0];
                this.sequenceWindow.RemoveAt(0);
            }

            return id;
        }

        private void IncreaseSequenceWindow(int by)
        {
            lock (this.sequenceWindow)
            {
                for (int i = 0; i < by; i++)
                {
                    this.sequenceWindow.Add(++this.largestsequencenum);
                }
            }
        }

        private void ConnectionReader()
        {
            byte[] netbios_header = new byte[4];
            byte[] data;
            int datalength;
            while (true)
            {
                SpinWait.SpinUntil(() =>
                {
                    return !this.stream.DataAvailable && this.maintainConnection;
                });

                if (!this.maintainConnection)
                {
                    break;
                }

                netbios_header = Packet.ForceRead(this.stream, netbios_header, 4);
                datalength = BitConverterBE.ToUShort(netbios_header, 2);
                data = new byte[datalength];
                data = Packet.ForceRead(this.stream, data, datalength);

                Packet[] packets = Packet.Read((this.Dialect == 0 ? SmbVersion.V21 : this.Dialect), this.RequireSigning, new MemoryStream(data, 0, datalength, false, false));

                for (int i = 0; i < packets.Length; i++)
                {
                    this.receivedPackets.Add(packets[i].MessageId, packets[i]);
                    this.IncreaseSequenceWindow(packets[i].CreditResponse);
                }
            }
        }
    }
}