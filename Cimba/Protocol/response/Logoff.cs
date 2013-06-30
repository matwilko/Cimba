namespace Cimba.Protocol
{
    using System.IO;

    internal class LogoffResponse : Packet
    {
        internal LogoffResponse()
        {
            this.Command = PacketType.Logoff;
            this.IsRequest = false;
        }

        internal static LogoffResponse Read(MemoryStream stream)
        {
            byte[] buffer = new byte[4];
            stream.Read(buffer, 0, 4);

            // StructureSize (2 bytes) - MUST be 4
            if (BitConverterLE.ToShort(buffer, 0) != 4)
            {
                throw new SmbPacketException("Malformed Logoff Response");
            }

            // Reserved (2 bytes) - MUST ignore on receipt
            return new LogoffResponse();
        }

        protected override byte[] Generate()
        {
            byte[] packet = new byte[4];

            // StrucutreSize (2 bytes) - MUST be 4
            BitConverterLE.GetBytes((ushort)4).CopyTo(packet, 0);

            // Reserved (2 bytes) - MUST set to 0
            return packet;
        }
    }
}
