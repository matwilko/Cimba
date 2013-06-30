namespace Cimba.Protocol
{
    using System;
    using System.IO;

    internal class SetInfoRequest : Packet
    {
        internal SetInfoRequest(FILE_ID fileId, SetInfo_FileInformationClass fileInfoClass, byte[] buffer)
        {
            this.Command = PacketType.Set_Info;

            this.FileId = fileId;
            this.InfoType = Protocol.InfoType.FILE;
            this.FileInfoClass = (byte)fileInfoClass;
            this.Buffer = buffer;
            this.AdditionalInformation = (QueryAdditionalInformation)0;
        }

        internal InfoType InfoType { get; set; }

        internal byte FileInfoClass { get; set; }

        internal QueryAdditionalInformation AdditionalInformation { get; set; }

        internal FILE_ID FileId { get; set; }

        internal byte[] Buffer { get; set; }
        
        internal static SetInfoRequest Read(MemoryStream stream)
        {
            throw new NotImplementedException();
        }

        protected override byte[] Generate()
        {
            byte[] buffer = new byte[32 + this.Buffer.Length];

            // StructureSize (2 bytes)
            BitConverterLittleEndian.GetBytes((ushort)33).CopyTo(buffer, 0);

            // InfoType (1 byte)
            BitConverterLittleEndian.GetBytes((byte)this.InfoType).CopyTo(buffer, 2);

            // FileInfoClass (1 byte)
            BitConverterLittleEndian.GetBytes(this.FileInfoClass).CopyTo(buffer, 3);

            // BufferLength (4 bytes)
            BitConverterLittleEndian.GetBytes((uint)this.Buffer.Length).CopyTo(buffer, 4);

            // BufferOffset (2 bytes)
            BitConverterLittleEndian.GetBytes((ushort)(32 + Packet.HeaderLength)).CopyTo(buffer, 8);

            // Reserved (2 bytes) - MUST NOT be used and MUST be reserved

            // AdditionalInformation (4 bytes)
            BitConverterLittleEndian.GetBytes((uint)this.AdditionalInformation).CopyTo(buffer, 12);

            // FileId (16 bytes)
            this.FileId.Flatten().CopyTo(buffer, 16);

            // Buffer(variable)
            this.Buffer.CopyTo(buffer, 32);

            return buffer;
        }
    }
}
