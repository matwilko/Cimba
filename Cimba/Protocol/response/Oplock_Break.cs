namespace Cimba.Protocol
{
    using System;
    using System.IO;

    internal class OplockBreakNotification : Packet
    {
        internal OplockBreakNotification()
        {
            this.Command = PacketType.OpLock_Break;
            this.IsRequest = false;
        }

        internal FILE_ID FileId { get; set; }

        internal OplockLevel OplockLevel { get; set; }

        internal static OplockBreakNotification Read(MemoryStream stream)
        {
            if (BitConverterLittleEndian.ToUShort(stream) != 24)
            {
                throw new SmbPacketException("Invalid OplockBreakNotification");
            }

            OplockBreakNotification packet = new OplockBreakNotification();
            packet.OplockLevel = (OplockLevel)(byte)stream.ReadByte();

            // Reserved (1 byte)
            stream.Seek(1, SeekOrigin.Current);

            // Reserved2 (4 bytes)
            stream.Seek(4, SeekOrigin.Current);

            // FileId (16 bytes)
            packet.FileId = new FILE_ID(BitConverterLittleEndian.ToULong(stream), BitConverterLittleEndian.ToULong(stream));

            return packet;
        }

        protected override byte[] Generate()
        {
            throw new NotImplementedException();
        }
    }
}
