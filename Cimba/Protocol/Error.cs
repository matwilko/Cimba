namespace Cimba.Protocol
{
    using System.IO;

    internal class ErrorResponse : Packet
    {
        internal ErrorResponse(Packet request, byte[] errorData = null)
        {
            this.Command = request.Command;
            this.MessageId = request.MessageId;
            this.SessionId = request.SessionId;
            this.TreeId = request.TreeId;
            if (errorData == null)
            {
                this.ErrorData = new byte[0];
            }
        }

        private ErrorResponse()
        {
        }

        internal byte[] ErrorData { get; set; }

        internal static ErrorResponse Read(MemoryStream stream)
        {
            byte[] buffer = new byte[8];
            stream.Read(buffer, 0, 8);

            // StructureSize (2 bytes) - MUST be 9
            if (BitConverterLittleEndian.ToUShort(buffer, 0) != 9)
            {
                throw new SmbPacketException("Malformed Error Response");
            }

            // Reserved (2 bytes)
            // ByteCount (4 bytes)
            uint bytecount = BitConverterLittleEndian.ToUInt(buffer, 4);

            ErrorResponse packet = new ErrorResponse();

            // ErrorData
            packet.ErrorData = new byte[bytecount];
            stream.Read(packet.ErrorData, 0, (int)bytecount);

            return packet;
        }

        protected override byte[] Generate()
        {
            byte[] buffer = new byte[8 + this.ErrorData.Length];

            // StructureSize (2 bytes)
            BitConverterLittleEndian.GetBytes((ushort)9).CopyTo(buffer, 0);

            // Reserved (2 bytes)
            // ByteCount (4 bytes)
            BitConverterLittleEndian.GetBytes((uint)this.ErrorData.Length).CopyTo(buffer, 4);

            // ErrorData (variable)
            this.ErrorData.CopyTo(buffer, 8);

            return buffer;
        }
    }
}
