namespace Cimba.Protocol
{
    using System;
    using System.IO;

    internal class LeaseBreakNotification : Packet
    {
        internal bool AcknowledgementRequired { get; set; }

        internal byte[] LeaseKey { get; set; }

        internal LeaseState CurrentLeaseState { get; set; }

        internal LeaseState NewLeaseState { get; set; }

        internal static LeaseBreakNotification Read(MemoryStream stream)
        {
            if (BitConverterLittleEndian.ToUShort(stream) != 44)
            {
                throw new SmbPacketException("Invalid LeaseBreakNotification");
            }

            LeaseBreakNotification packet = new LeaseBreakNotification();

            // Reserved (2 bytes)
            stream.Seek(2, SeekOrigin.Current);

            // Flags (4 bytes)
            packet.AcknowledgementRequired = BitConverterLittleEndian.ToUInt(stream) == 0x00000001;

            // LeaseKey (16 bytes)
            packet.LeaseKey = new byte[16];
            stream.Read(packet.LeaseKey, 0, 16);

            // CurrentLeaseState (4 bytes)
            packet.CurrentLeaseState = (LeaseState)BitConverterLittleEndian.ToUInt(stream);

            // NewLeaseState (4 bytes)
            packet.NewLeaseState = (LeaseState)BitConverterLittleEndian.ToUInt(stream);

            // BreakReason (4 bytes) - MUST NOT be used and MUST be reserved
            // AccessMaskHint (4 bytes) - MUST NOT be used and MUST be reserved
            // ShareMaskHint (4 bytes) - MUST NOT be used and MUST be reserved
            return packet;
        }

        protected override byte[] Generate()
        {
            throw new NotImplementedException();
        }
    }
}
