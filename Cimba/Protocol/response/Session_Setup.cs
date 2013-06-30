namespace Cimba.Protocol
{
    using System.IO;

    internal class SessionSetupResponse : Packet
    {
        internal SessionSetupResponse()
        {
            this.Command = PacketType.Session_Setup;
            this.IsRequest = false;
        }

        internal byte[] SecurityBuffer { get; set; }

        internal ushort SessionFlags { get; set; }

        internal static SessionSetupResponse Read(MemoryStream stream)
        {
            // TODO: Rewrite!
            SessionSetupResponse newpacket = new SessionSetupResponse();

            byte[] structure = new byte[8];
            stream.Read(structure, 0, 8);

            ushort securityBufferOffset = BitConverterLE.ToUShort(structure, 4);
            ushort securityBufferLength = BitConverterLE.ToUShort(structure, 6);

            byte[] buffer = new byte[securityBufferLength];
            stream.Seek(securityBufferOffset, SeekOrigin.Begin);
            stream.Read(buffer, 0, securityBufferLength);

            newpacket.SecurityBuffer = buffer;

            return newpacket;
        }

        protected override byte[] Generate()
        {
            byte[] buffer = new byte[8 + this.SecurityBuffer.Length];

            // StructureSize (2 bytes)
            BitConverterLE.GetBytes((ushort)9).CopyTo(buffer, 0);

            // SessionFlags (2 bytes)
            BitConverterLE.GetBytes((ushort)this.SessionFlags).CopyTo(buffer, 2);

            // SecurityBufferOffset (2 bytes)
            BitConverterLE.GetBytes((ushort)(8 + Packet.HeaderLength)).CopyTo(buffer, 4);

            // SecurityBufferLength (2 bytes)
            BitConverterLE.GetBytes((ushort)this.SecurityBuffer.Length).CopyTo(buffer, 6);

            // Buffer (variable)
            this.SecurityBuffer.CopyTo(buffer, 8);

            return buffer;
        }
    }
}
