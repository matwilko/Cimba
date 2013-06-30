namespace Cimba.Protocol
{
    internal class ChangeNotifyRequest : Packet
    {
        internal ChangeNotifyRequest(FILE_ID fileId, NOTIFY_CHANGE completionFilter, uint outputBufferLength, bool watchTree = false)
        {
            this.Command = PacketType.Change_Notify;

            this.FileId = fileId;
            this.CompletionFilter = completionFilter;
            this.OutputBufferLength = outputBufferLength;
            this.WatchTree = watchTree;
        }

        internal FILE_ID FileId { get; set; }

        internal bool WatchTree { get; set; }

        internal uint OutputBufferLength { get; set; }

        internal NOTIFY_CHANGE CompletionFilter { get; set; }

        protected override byte[] Generate()
        {
            byte[] buffer = new byte[32];

            // StructureSize (2 bytes)
            BitConverterLittleEndian.GetBytes((ushort)32).CopyTo(buffer, 0);

            // Flags (2 bytes)
            if (this.WatchTree)
            {
                BitConverterLittleEndian.GetBytes((ushort)0x0001).CopyTo(buffer, 2);
            }

            // OutputBufferLength (4 bytes)
            BitConverterLittleEndian.GetBytes(this.OutputBufferLength).CopyTo(buffer, 4);

            // FileId (16 bytes)
            this.FileId.Flatten().CopyTo(buffer, 8);

            // CompletionFilter (4 bytes)
            BitConverterLittleEndian.GetBytes((uint)this.CompletionFilter).CopyTo(buffer, 24);

            // Reserved (4 bytes) - MUST NOT be used and MUST be reserved
            return buffer;
        }
    }
}
