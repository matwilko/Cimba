namespace Cimba.Protocol
{
    using System.IO;

    internal class FlushResponse : Packet
    {
        internal FlushResponse()
        {
            this.Command = PacketType.Flush;
            this.IsRequest = false;
        }

        internal static FlushResponse Read(MemoryStream stream)
        {
            if (BitConverterLittleEndian.ToUShort(stream) != 4)
            {
                throw new SmbPacketException("Invalid FlushResponse");
            }

            return new FlushResponse();
        }

        protected override byte[] Generate()
        {
            byte[] buffer = new byte[4];

            // StructureSize (2 bytes)
            BitConverterLittleEndian.GetBytes((ushort)4).CopyTo(buffer, 0);

            // Reserved (2 bytes)
            BitConverterLittleEndian.GetBytes((ushort)0).CopyTo(buffer, 2);

            return buffer;
        }
    }
}
