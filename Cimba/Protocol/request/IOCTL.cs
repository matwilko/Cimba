namespace Cimba.Protocol
{
    using System.IO;

    internal class IOCTLRequest : Packet
    {
        internal IOCTLRequest()
        {
            this.Command = PacketType.IOCTL;
        }

        internal uint CtlCode { get; set; }

        internal FILE_ID FileId { get; set; }

        internal uint MaxInputResponse { get; set; }

        internal uint MaxOutputResponse { get; set; }

        internal bool IsFSCTL { get; set; }

        internal byte[] IN { get; set; }

        internal static IOCTLRequest Read(MemoryStream stream)
        {
            // StructureSize (2 bytes)
            if (BitConverterLE.ToUShort(stream) != 57)
            {
                throw new SmbPacketException("Invalid IOCTLRequest");
            }

            IOCTLRequest packet = new IOCTLRequest();

            // Reserved (2 bytes)
            stream.Seek(2, SeekOrigin.Current);

            // CtlCode (4 bytes)
            packet.CtlCode = BitConverterLE.ToUInt(stream);

            // FileId (16 bytes)
            byte[] fileid = new byte[16];
            stream.Read(fileid, 0, 16);
            packet.FileId = new FILE_ID(fileid);

            // InputOffset (4 bytes)
            uint inputOffset = BitConverterLE.ToUInt(stream);

            // InputCount (4 bytes)
            uint inputLength = BitConverterLE.ToUInt(stream);

            // MaxInputResponse (4 bytes)
            packet.MaxInputResponse = BitConverterLE.ToUInt(stream);

            // OutputOffset (4 bytes)
            stream.Seek(4, SeekOrigin.Current);

            // OutputCount (4 bytes)
            stream.Seek(4, SeekOrigin.Current);

            // MaxOutputResponse (4 bytes)
            packet.MaxOutputResponse = BitConverterLE.ToUInt(stream);

            // Flags (4 bytes)
            packet.IsFSCTL = BitConverterLE.ToUInt(stream) == 1;

            // Reserved2 (4 bytes)

            // Buffer (variable)
            stream.Seek(inputOffset, SeekOrigin.Begin);
            packet.IN = new byte[inputLength];

            return packet;
        }

        protected override byte[] Generate()
        {
            throw new System.NotImplementedException();
        }
    }
}
