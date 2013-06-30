namespace Cimba.Protocol
{
    using System;
    using System.Collections.Generic;
    using System.IO;

    internal class LockRequest : Packet
    {
        internal LockRequest(List<LOCK_ELEMENT> locks, SmbVersion version)
        {
            this.Command = PacketType.Lock;

            this.LockSequence = 0;
            this.Locks = locks;
            this.Version = version;
        }

        internal List<LOCK_ELEMENT> Locks { get; set; }

        internal uint LockSequence { get; set; }

        internal FILE_ID FileId { get; set; }

        internal SmbVersion VersionInUse { get; set; }

        internal static LogoffRequest Read(MemoryStream stream)
        {
            throw new NotImplementedException();
        }

        protected override byte[] Generate()
        {
            byte[] buffer = new byte[48 + (24 * (this.Locks.Count - 1))];

            // StructureSize (2 bytes)
            BitConverterLittleEndian.GetBytes((ushort)48).CopyTo(buffer, 0);

            // LockCount (2 bytes)
            BitConverterLittleEndian.GetBytes((ushort)this.Locks.Count).CopyTo(buffer, 2);

            // LockSequence (4 bytes)
            if (this.VersionInUse == SmbVersion.V21)
            {
                BitConverterLittleEndian.GetBytes((uint)this.LockSequence).CopyTo(buffer, 4);
            }

            // FileId (16 bytes)
            this.FileId.Flatten().CopyTo(buffer, 8);

            // Locks
            int offset = 24;
            foreach (LOCK_ELEMENT lockelem in this.Locks)
            {
                lockelem.Flatten().CopyTo(buffer, offset);
                offset += 24;
            }

            return buffer;
        }
    }
}
