namespace Cimba.Protocol
{
    internal class OplockBreakAcknowledgement : Packet
    {
        internal OplockBreakAcknowledgement(FILE_ID fileId, OplockLevel oplockLevel)
        {
            this.Command = PacketType.OpLock_Break;

            this.FileId = fileId;
            this.OplockLevel = oplockLevel;
        }

        internal FILE_ID FileId { get; set; }

        internal OplockLevel OplockLevel { get; set; }

        protected override byte[] Generate()
        {
            byte[] buffer = new byte[24];

            // StructureSize (2 bytes)
            BitConverterLE.GetBytes((ushort)24).CopyTo(buffer, 0);

            // OplockLevel (1 byte)
            buffer[2] = (byte)this.OplockLevel;

            // Reserved (1 byte)
            // Reserved2 (4 bytes)
            // FileId (16 bytes)
            BitConverterLE.GetBytes(this.FileId.Persistent).CopyTo(buffer, 8);
            BitConverterLE.GetBytes(this.FileId.Volatile).CopyTo(buffer, 16);

            return buffer;
        }
    }
}
