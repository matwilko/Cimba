namespace Cimba.Protocol
{
    using System.IO;

    internal class CancelRequest : Packet
    {
        internal CancelRequest()
        {
            this.Command = PacketType.Cancel;
        }

        internal static CancelRequest Read(MemoryStream stream)
        {
            if (BitConverterLittleEndian.ToUShort(stream) != 4)
            {
                throw new SmbPacketException("Invalid cancelRequest");
            }

            return new CancelRequest();
        }

        protected override byte[] Generate()
        {
            byte[] buffer = new byte[4];

            // StructureSize (2 bytes)
            BitConverterLittleEndian.GetBytes((ushort)4).CopyTo(buffer, 0);

            // Reserved (2 bytes) - MUST NOT be used and MUST be reserved
            return buffer;
        }
    }
}
