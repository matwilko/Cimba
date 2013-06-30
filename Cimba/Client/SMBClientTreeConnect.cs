namespace Cimba.Client
{
    using Cimba.Protocol;

    public class SmbClientTreeConnect
    {
        public bool Valid { get; internal set; }

        public string ShareName { get; private set; }

        public SmbClientSession Session { get; private set; }

        public bool IsDfsShare { get; private set; }

        internal uint TreeConnectId { get; private set; }

        public void Disconnect()
        {
            this.Session.Connection.RemoveOpenByTreeConnect(this);
            this.ReceivePacket(this.SendPacket(new TreeDisconnectRequest()));

            // TODO: ERROR CHECKING
            this.Valid = false;
        }

        internal static SmbClientTreeConnect Connect(SmbClientSession session, string shareName)
        {
            TreeConnectRequest req = new TreeConnectRequest(shareName);
            Packet response = session.Connection.ReceivePacket(session.SendPacket(req));
            if (response is ErrorResponse)
            {
                ErrorResponse error = (ErrorResponse)response;
                if (error.Status == NTSTATUS.STATUS_BAD_NETWORK_NAME)
                {
                    throw new SmbTreeConnectException("Share not found");
                }

                if (error.Status == NTSTATUS.STATUS_ACCESS_DENIED)
                {
                    throw new SmbTreeConnectException("Access Denied");
                }

                throw new SmbTreeConnectException("Unknown Error");
            }

            TreeConnectResponse resp = (TreeConnectResponse)response;

            switch (resp.Type)
            {
                case TreeConnectResponse.ShareType.DISK:
                    return new SmbClientTreeConnect_Share(resp, session, shareName);
                case TreeConnectResponse.ShareType.PIPE:
                    return new SmbClientTreeConnect_Pipe(resp, session, shareName);
                /*case TreeConnectResponse.ShareType.PRINT:
                    // TODO*/
                default:
                    throw new SmbTreeConnectException("Unknown Share Type");
            }
        }

        internal ulong SendPacket(Packet packet)
        {
            packet.TreeId = this.TreeConnectId;
            return this.Session.SendPacket(packet);
        }

        internal Packet ReceivePacket(ulong messageId)
        {
            return this.Session.ReceivePacket(messageId);
        }

        internal void SetCommonProperties(TreeConnectResponse response, SmbClientSession session, string shareName)
        {
            this.TreeConnectId = response.TreeId;
            this.ShareName = shareName;
            this.IsDfsShare = response.Flags.HasFlag(TreeConnectResponse.ShareFlags.DFS);
            this.Session = session;
            this.Valid = true;
        }
    }
}
