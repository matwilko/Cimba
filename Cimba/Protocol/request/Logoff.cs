namespace Cimba.Protocol
{
    using System.IO;

    internal class LogoffRequest : Packet
    {
        internal LogoffRequest()
        {
            this.Command = PacketType.Logoff;
        }

        internal static LogoffRequest Read(MemoryStream stream)
        {
            byte[] buffer = new byte[4];
            stream.Read(buffer, 0, 4);

            // StructureSize (2 bytes) - MUST be 4
            if (BitConverterLE.ToShort(buffer, 0) != 4)
            {
                throw new SmbPacketException("Malformed Logoff Request");
            }

            // Reserved (2 bytes) - MUST ignore on receipt
            return new LogoffRequest();
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
