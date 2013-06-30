namespace Cimba.Protocol
{
    using System.IO;

    internal class QueryInfoRequest : Packet
    {
        internal QueryInfoRequest(FILE_ID fileId, QueryInfo_FileInformationClass fileInformationClass, uint outputBufferLength, byte[] inputBuffer = null)
        {
            this.Command = PacketType.Query_Info;

            this.FileId = fileId;
            this.InfoType = Protocol.InfoType.FILE;
            this.FileInfoClass = (byte)fileInformationClass;
            this.OutputBufferLength = outputBufferLength;
            if (inputBuffer == null)
            {
                inputBuffer = new byte[0];
            }

            this.InputBuffer = inputBuffer;

            this.AdditionalInformation = (QueryAdditionalInformation)0;
            this.Flags = (QueryFlags)0;
        }

        private QueryInfoRequest()
        {
        }

        internal FILE_ID FileId { get; set; }

        internal InfoType InfoType { get; set; }

        internal byte FileInfoClass { get; set; }

        internal uint OutputBufferLength { get; set; }

        internal byte[] InputBuffer { get; set; }

        internal QueryAdditionalInformation AdditionalInformation { get; set; }

        internal QueryFlags Flags { get; set; }

        internal static QueryInfoRequest Read(MemoryStream stream)
        {
            return new QueryInfoRequest();
        }

        protected override byte[] Generate()
        {
            byte[] buffer = new byte[40 + this.InputBuffer.Length];

            // StructureSize (2 bytes)
            BitConverterLE.GetBytes((ushort)41).CopyTo(buffer, 0);

            // InfoType (1 byte)
            buffer[2] = (byte)this.InfoType;

            // FileInfoClass (1 byte)
            buffer[3] = this.FileInfoClass;

            // OutputBufferLength (4 bytes)
            BitConverterLE.GetBytes(this.OutputBufferLength).CopyTo(buffer, 4);

            // InputBufferOffset (2 bytes)
            if (this.InputBuffer.Length > 0)
            {
                BitConverterLE.GetBytes((ushort)40).CopyTo(buffer, 8);
            }

            // Reserved (2 bytes) - MUST NOT be used and MUST be reserved
            // InputBufferLength (4 bytes)
            BitConverterLE.GetBytes((uint)this.InputBuffer.Length).CopyTo(buffer, 12);

            // AdditionalInformation (4 bytes)
            BitConverterLE.GetBytes((uint)this.AdditionalInformation).CopyTo(buffer, 16);

            // Flags (4 bytes)
            BitConverterLE.GetBytes((uint)this.Flags).CopyTo(buffer, 20);

            // FileId (16 bytes)
            this.FileId.Flatten().CopyTo(buffer, 24);

            // Buffer (variable)
            this.InputBuffer.CopyTo(buffer, 40);

            return buffer;
        }
    }
}
