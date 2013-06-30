namespace Cimba.Protocol
{
    using System.IO;

    internal class LockResponse : Packet
    {
        internal LockResponse()
        {
            this.Command = PacketType.Logoff;
            this.IsRequest = false;
        }

        internal static LockResponse Read(MemoryStream stream)
        {
            // StructureSize (2 bytes) - MUST be 4
            if (BitConverterLE.ToShort(stream) != 4)
            {
                throw new SmbPacketException("Invalid LockResponse");
            }

            // Reserved (2 bytes) - MUST ignore on receipt
            return new LockResponse();
        }

        protected override byte[] Generate()
        {
            byte[] packet = new byte[4];

            // StructureSize (2 bytes) - MUST be 4
            BitConverterLE.GetBytes((ushort)4).CopyTo(packet, 0);

            // Reserved (2 bytes) - MUST set to 0
            return packet;
        }
    }
}
