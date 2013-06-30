namespace Cimba.Server
{
    using System;
    using System.Collections.Generic;
    using System.Threading;
    using Cimba.Client;
    using Cimba.Protocol;
    using Cimba.Protocol.External.Microsoft;

    public delegate SmbClientCredentials AuthenticateClientDelegate(string Domain, string Username);

    public delegate Tuple<NewTreeConnectDelegate, CanAccessShareDelegate, GetShareDelegate> NewSessionDelegate(SmbServerSession session);

    public class SmbServerSession
    {
        private readonly AuthenticateClientDelegate authenticatedelegate;

        private readonly NewSessionDelegate newsessiondelegate;

        private NewTreeConnectDelegate newTreeConnect;

        private CanAccessShareDelegate canAccessShare;

        private GetShareDelegate getShare;

        private ulong ntlmChallenge;

        private byte[] sessionKey;

        private byte[] mechList;

        private Dictionary<uint, SmbServerTreeConnect> treeConnects = new Dictionary<uint, SmbServerTreeConnect>();

        internal SmbServerSession(SmbServerConnection conn, Packet packet, AuthenticateClientDelegate auth, NewSessionDelegate newsess)
        {
            SessionSetupRequest request = (SessionSetupRequest)packet;
            this.SessionId = (ulong)(new Random()).NextInt64();
            this.authenticatedelegate = auth;
            this.newsessiondelegate = newsess;
            this.Connection = conn;

            SessionSetupResponse response = new SessionSetupResponse();
            this.ntlmChallenge = (ulong)(new Random()).NextInt64();
            this.mechList = SPNG.ReadNegTokenInit(request.SecurityBuffer);
            response.SecurityBuffer = SPNG.GenerateFirstNegTokenResp(this.ntlmChallenge);
            response.Status = NTSTATUS.STATUS_MORE_PROCESSING_REQUIRED;

            this.SendPacket(request, response);
        }

        public bool Valid { get; private set; }

        public SmbServerConnection Connection { get; private set; }

        internal ulong SessionId { get; private set; }

        internal void ProcessPacket(Packet packet)
        {
            if (packet is SessionSetupRequest)
            {
                SessionSetupRequest request = (SessionSetupRequest)packet;
                Tuple<bool, byte[], byte[]> neg = SPNG.ReadFinalToken(request.SecurityBuffer, this.ntlmChallenge, this.authenticatedelegate, this.mechList);
                if (!neg.Item1)
                {
                    this.Valid = false;
                    this.Connection.ClientError(request, NTSTATUS.STATUS_LOGON_FAILURE);
                    this.Connection.Disconnect();
                }
                else
                {
                    SessionSetupResponse response = new SessionSetupResponse();
                    response.SecurityBuffer = neg.Item2;
                    this.sessionKey = neg.Item3;
                    this.SendPacket(request, response);
                    Tuple<NewTreeConnectDelegate, CanAccessShareDelegate, GetShareDelegate> delegates = this.Connection.NewSession(this);
                    this.newTreeConnect = delegates.Item1;
                    this.canAccessShare = delegates.Item2;
                    this.getShare = delegates.Item3;
                }
            }
            else if (packet is TreeConnectRequest)
            {
                SpinWait.SpinUntil(() =>
                    {
                        return this.canAccessShare != null && this.newTreeConnect != null && this.getShare != null;
                    });

                TreeConnectRequest request = (TreeConnectRequest)packet;
                try
                {
                    string[] shareparts = request.ShareName.Split('\\');
                    string shareName = shareparts[shareparts.Length - 1].Equals(string.Empty) ? shareparts[shareparts.Length - 2] : shareparts[shareparts.Length - 1];

                    SmbServerShare share = this.getShare(shareName);
                    if (this.canAccessShare(shareName))
                    {
                        SmbServerTreeConnect treeConnect = new SmbServerTreeConnect(this, (TreeConnectRequest)packet, share, this.newTreeConnect);
                        this.treeConnects.Add(treeConnect.TreeId, treeConnect);
                    }
                    else
                    {
                        this.Connection.ClientError(request, NTSTATUS.STATUS_ACCESS_DENIED);
                    }
                }
                catch (SmbTreeConnectException)
                {
                    this.Connection.ClientError(request, NTSTATUS.STATUS_BAD_NETWORK_NAME);
                }
            }
            else if (packet is TreeDisconnectRequest)
            {
                if (this.treeConnects.ContainsKey(packet.TreeId))
                {
                    this.treeConnects.Remove(packet.TreeId);
                    TreeDisconnectResponse response = new TreeDisconnectResponse();
                    response.TreeId = packet.TreeId;
                    this.SendPacket(packet, response);
                }
                else
                {
                    this.Connection.ClientError(packet, NTSTATUS.STATUS_NETWORK_NAME_DELETED);
                }
            }
            else
            {
                if (this.treeConnects.ContainsKey(packet.TreeId))
                {
                    this.treeConnects[packet.TreeId].ProcessPacket(packet);
                }
                else
                {
                    this.Connection.ClientError(packet, NTSTATUS.STATUS_NETWORK_NAME_DELETED);
                }
            }
        }

        internal void SendPacket(Packet request, Packet response)
        {
            response.SessionId = this.SessionId;
            if (this.sessionKey != null && request.MessageId >= 2)
            {
                response.SignPacket(this.sessionKey);
            }

            this.Connection.SendPacket(request, response);
        }
    }
}