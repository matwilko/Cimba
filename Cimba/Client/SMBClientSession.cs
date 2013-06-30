namespace Cimba.Client
{
    using System;
    using System.Collections.Generic;
    using Cimba.Protocol;
    using Cimba.Protocol.External.Microsoft;

    public class SmbClientSession
    {
        public readonly SmbClientConnection Connection;

        private readonly SmbClientCredentials userCredentials;

        private ulong sessionId;

        private Dictionary<uint, SmbClientTreeConnect> treeConnectTableByID = new Dictionary<uint, SmbClientTreeConnect>();

        private Dictionary<string, SmbClientTreeConnect> treeConnectTableByShareName = new Dictionary<string, SmbClientTreeConnect>();

        private byte[] sessionKey;

        private bool shouldSign;

        ////private byte[] targetInfo;

        internal SmbClientSession(SmbClientConnection conn, SmbClientCredentials cred, byte[] gssNegotiateToken)
        {
            this.Connection = conn;
            this.userCredentials = cred;
            this.shouldSign = conn.RequireSigning;

            Packet returnpacket;

            byte[] sb = SPNG.ReadNegTokenInit2(gssNegotiateToken);

            SessionSetupRequest first_ss = new SessionSetupRequest(
                (this.Connection.RequireSigning ? Negotiate_SecurityMode.SigningRequired : Negotiate_SecurityMode.SigningEnabled),
                sb);

            SessionSetupResponse return_ss;
            returnpacket = this.Connection.ReceivePacket(this.Connection.SendPacket(first_ss));
            if (returnpacket is ErrorResponse)
            {
                ////ErrorResponse error = (ErrorResponse)returnpacket;
                throw new SmbSessionException("Unknown Error Occured");
            }

            return_ss = (SessionSetupResponse)returnpacket;
            this.sessionId = return_ss.SessionId;

            Tuple<byte[], byte[]> respAndKey = SPNG.ReadFirstNegTokenResp(return_ss.SecurityBuffer, this.userCredentials);
            sb = respAndKey.Item1;
            this.sessionKey = respAndKey.Item2;

            SessionSetupRequest new_ss = new SessionSetupRequest(Negotiate_SecurityMode.SigningEnabled, sb, 0);
            new_ss.SessionId = this.sessionId;

            returnpacket = this.Connection.ReceivePacket(this.Connection.SendPacket(new_ss));
            if (returnpacket is ErrorResponse)
            {
                ErrorResponse error = (ErrorResponse)returnpacket;
                if (error.Status == NTSTATUS.STATUS_LOGON_FAILURE)
                {
                    throw new SmbSessionException("Incorrect Credentials");
                }
            }

            return_ss = (SessionSetupResponse)returnpacket;

            if (return_ss.Status != 0x00)
            {
                throw new SmbSessionException("Session Setup Failed");
            }
            else
            {
                this.Valid = true;
            }
        }

        public bool Valid { get; private set; }

        public void Logoff()
        {
            this.Valid = false;

            foreach (SmbClientTreeConnect treeConnect in this.treeConnectTableByID.Values)
            {
                treeConnect.Disconnect();
            }

            LogoffRequest request = new LogoffRequest();
            request.SessionId = this.sessionId;

            this.Connection.ReceivePacket(this.Connection.SendPacket(request));

            this.Valid = false;

            this.Connection.RemoveSession(this.userCredentials, this.sessionId);
        }

        public SmbClientTreeConnect ConnectTree(string shareName)
        {
            SmbClientTreeConnect tree = SmbClientTreeConnect.Connect(this, shareName);

            this.treeConnectTableByID.Add(tree.TreeConnectId, tree);
            this.treeConnectTableByShareName.Add(tree.ShareName, tree);

            return tree;
        }

        internal ulong SendPacket(Packet packet)
        {
            packet.SessionId = this.sessionId;
            packet.SignPacket(this.sessionKey);
            return this.Connection.SendPacket(packet);
        }

        internal Packet ReceivePacket(ulong messageId)
        {
            Packet packet = this.Connection.ReceivePacket(messageId);
            if (packet.VerifySignature(this.sessionKey, this.Connection.RequireSigning))
            {
                return packet;
            }
            else
            {
                throw new SmbSessionException("Invalid signature");
            }
        }
    }
}
