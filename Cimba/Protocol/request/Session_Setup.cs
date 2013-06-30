namespace Cimba.Protocol
{
    using System.IO;

    internal class SessionSetupRequest : Packet
    {
        internal SessionSetupRequest(Negotiate_SecurityMode securityMode, byte[] securityBuffer, ulong previousSessionId = 0, bool supportsDFS = false)
        {
            this.SecurityMode = securityMode;
            this.SecurityBuffer = securityBuffer;
            this.PreviousSessionId = previousSessionId;
            this.SupportsDFS = supportsDFS;

            this.Command = PacketType.Session_Setup;
            this.IsRequest = true;
            this.SessionId = this.PreviousSessionId;
        }

        internal SessionSetupRequest()
        {
        }

        internal Negotiate_SecurityMode SecurityMode { get; set; }

        internal bool SupportsDFS { get; set; }

        internal ulong PreviousSessionId { get; set; }

        internal byte[] SecurityBuffer { get; set; }

        internal static SessionSetupRequest Read(MemoryStream stream)
        {
            // StructureSize (2 bytes)
            ushort ss = BitConverterLE.ToUShort(stream);
            if (ss != 24 && ss != 25)
            {
                throw new SmbPacketException("Invalid SessionSetupRequest");
            }

            SessionSetupRequest packet = new SessionSetupRequest();

            // VcNumber (1 byte) - client MUST set this field to 0
            stream.Seek(1, SeekOrigin.Current);

            // SecurityMode (1 byte)
            packet.SecurityMode = (Negotiate_SecurityMode)(byte)stream.ReadByte();

            // Capabilities (4 bytes)
            packet.SupportsDFS = (BitConverterLE.ToUInt(stream) & 0x02) == 0x02;

            // Channel (4 bytes) - field MUST NOT be used and MUST be reserved - MUST ignore
            stream.Seek(4, SeekOrigin.Current);

            // SecurityBufferOffset (2 bytes)
            int bufferOffset = BitConverterLE.ToUShort(stream);

            // SecurityBufferLength (2 bytes)
            int bufferLength = BitConverterLE.ToUShort(stream);

            // PreviousSessionId (8 bytes)
            packet.PreviousSessionId = BitConverterLE.ToULong(stream);

            // Buffer (variable)
            stream.Seek(bufferOffset, SeekOrigin.Begin);
            packet.SecurityBuffer = new byte[bufferLength];
            stream.Read(packet.SecurityBuffer, 0, bufferLength);

            return packet;
        }

        protected override byte[] Generate()
        {
            // IMPORTANT NOTE: [MS-SMB2] states that StructureSize should be 25 in all cases, however, the actual length of the structure is 24 bytes
            byte[] data = new byte[24 + this.SecurityBuffer.Length];

            // StructureSize (2 bytes)
            BitConverterLE.GetBytes((ushort)24).CopyTo(data, 0);

            // VcNumber (1 byte) - number of transport connections already established. Client MUST set to 0 regardless of outstanding connections
            BitConverterLE.GetBytes((byte)0).CopyTo(data, 2);

            // SecurityMode (1 byte)
            BitConverterLE.GetBytes((byte)(ushort)this.SecurityMode).CopyTo(data, 3);

            // Capabilities (4 bytes)
            BitConverterLE.GetBytes((uint)(this.SupportsDFS ? 0x00000001 : 0x00000000)).CopyTo(data, 4);

            // Channel (4 bytes) - MUST NOT be used and MUST be reserved

            // SecurityBufferOffset (2 bytes) - offset from beginning of SMB2 Header
            BitConverterLE.GetBytes((ushort)(Packet.HeaderLength + 24)).CopyTo(data, 12);

            // SecurityBufferLength (2 bytes)
            BitConverterLE.GetBytes((ushort)this.SecurityBuffer.Length).CopyTo(data, 14);

            // PreviousSessionId (8 bytes)
            BitConverterLE.GetBytes(this.PreviousSessionId).CopyTo(data, 16);

            this.SecurityBuffer.CopyTo(data, 24);

            return data;
        }
    }
}
