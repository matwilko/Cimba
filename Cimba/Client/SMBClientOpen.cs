namespace Cimba.Client
{
    using System;
    using Cimba.Protocol;
    using Cimba.Protocol.External.Microsoft;

    public abstract class SmbClientOpen
    {
        [Flags]
        public enum FileAttributes
        {
            Normal = 0,
            Archive = 1,
            Compressed = 2,
            Encrypted = 4,
            Hidden = 8,
            Indexed = 16,
            ReadOnly = 32,
            System = 64
        }

        public SmbClientTreeConnect TreeConnect { get; internal set; }

        public OppurtunisticLockLevel OplockLevel { get; internal set; }

        public string FileName { get; internal set; }

        public bool Durable { get; internal set; }

        public bool ResilientHandle { get; internal set; }

        ////internal int LastDiconnectTime { get; set; }
        ////internal uint ResilientTimeout { get; set; } // Minimum time for which the server will hold this open while waiting for client to re-establish
        ////internal List<OperationBucket> OperationBuckets { get; set; }
        internal FILE_ID FileId { get; set; }

        public void Close(bool returnCorrectAttributes = true)
        {
            if (this.Durable)
            {
                // TODO: Durable file handle logic
            }
            else
            {
                CloseRequest request = new CloseRequest(this.FileId, returnCorrectAttributes);
                CloseResponse response = (CloseResponse)this.TreeConnect.ReceivePacket(this.TreeConnect.SendPacket(request));
                this.TreeConnect.Session.Connection.RemoveOpen(this);
            }
        }

        internal static OppurtunisticLockLevel ConvertOplockLevel(Create_Oplock_Level oplock)
        {
            switch (oplock)
            {
                case Create_Oplock_Level.BATCH:
                    return OppurtunisticLockLevel.Batch;
                case Create_Oplock_Level.EXCLUSIVE:
                    return OppurtunisticLockLevel.Exclusive;
                case Create_Oplock_Level.II:
                    return OppurtunisticLockLevel.II;
                case Create_Oplock_Level.NONE:
                    return OppurtunisticLockLevel.None;
                default:
                    throw new SmbTreeConnectException("Invalid Oppurtunistic Lock Level");
            }
        }

        internal static Create_Oplock_Level ConvertOplockLevel(OppurtunisticLockLevel oplock)
        {
            switch (oplock)
            {
                case OppurtunisticLockLevel.Batch:
                    return Create_Oplock_Level.BATCH;
                case OppurtunisticLockLevel.Exclusive:
                    return Create_Oplock_Level.EXCLUSIVE;
                case OppurtunisticLockLevel.II:
                    return Create_Oplock_Level.II;
                default:
                    throw new SmbTreeConnectException("Invalid Oppurtunistic Lock Level");
            }
        }

        internal static Create_Impersonation_Level ConvertImpLevel(ImpersonationLevel implevel)
        {
            switch (implevel)
            {
                case ImpersonationLevel.Anonymous:
                    return Create_Impersonation_Level.Anonymous;
                case ImpersonationLevel.Identification:
                    return Create_Impersonation_Level.Identification;
                case ImpersonationLevel.Impersonation:
                    return Create_Impersonation_Level.Impersonation;
                case ImpersonationLevel.Delegate:
                    return Create_Impersonation_Level.Delegate;
                default:
                    throw new SmbTreeConnectException("Invalid Impersonation Level");
            }
        }

        internal static ImpersonationLevel ConvertImpLevel(Create_Impersonation_Level implevel)
        {
            switch (implevel)
            {
                case Create_Impersonation_Level.Anonymous:
                    return ImpersonationLevel.Anonymous;
                case Create_Impersonation_Level.Identification:
                    return ImpersonationLevel.Identification;
                case Create_Impersonation_Level.Impersonation:
                    return ImpersonationLevel.Impersonation;
                case Create_Impersonation_Level.Delegate:
                    return ImpersonationLevel.Delegate;
                default:
                    throw new SmbTreeConnectException("Invalid Impersonation Level");
            }
        }

        internal static AccessMask.File_Pipe_Printer ConvertDesiredAccess(FileAccess filePermission, Access extendedAttributesPermission, Access attributePermission)
        {
            AccessMask.File_Pipe_Printer da = (AccessMask.File_Pipe_Printer)0x00000000;
            if (filePermission.HasFlag(FileAccess.Read))
            {
                da |= AccessMask.File_Pipe_Printer.READ_DATA;
            }

            if (filePermission.HasFlag(FileAccess.Write))
            {
                da |= AccessMask.File_Pipe_Printer.WRITE_DATA;
            }

            if (filePermission.HasFlag(FileAccess.Append))
            {
                da |= AccessMask.File_Pipe_Printer.APPEND_DATA;
            }

            if (filePermission.HasFlag(FileAccess.Delete))
            {
                da |= AccessMask.File_Pipe_Printer.DELETE;
            }

            if (filePermission.HasFlag(FileAccess.Execute))
            {
                da |= AccessMask.File_Pipe_Printer.EXECUTE;
            }

            if (extendedAttributesPermission.HasFlag(Access.Read))
            {
                da |= AccessMask.File_Pipe_Printer.READ_EA;
            }

            if (extendedAttributesPermission.HasFlag(Access.Write))
            {
                da |= AccessMask.File_Pipe_Printer.WRITE_EA;
            }

            if (attributePermission.HasFlag(Access.Read))
            {
                da |= AccessMask.File_Pipe_Printer.READ_ATTRIBUTES;
            }

            if (attributePermission.HasFlag(Access.Write))
            {
                da |= AccessMask.File_Pipe_Printer.WRITE_ATTRIBUTES;
            }

            return da;
        }

        internal static Create_Share_Access ConvertShareAccess(ShareAccess sa)
        {
            Create_Share_Access returnsa = (Create_Share_Access)0x00000000;
            if (sa.HasFlag(Cimba.ShareAccess.Read))
            {
                returnsa |= Create_Share_Access.SHARE_READ;
            }

            if (sa.HasFlag(Cimba.ShareAccess.Read))
            {
                returnsa |= Create_Share_Access.SHARE_READ;
            }

            if (sa.HasFlag(Cimba.ShareAccess.Read))
            {
                returnsa |= Create_Share_Access.SHARE_READ;
            }

            return returnsa;
        }

        internal static Create_Create_Disposition ConvertDisposition(OpenDisposition od)
        {
            switch (od)
            {
                case OpenDisposition.Open:
                    return Create_Create_Disposition.OPEN;
                case OpenDisposition.Overwrite:
                    return Create_Create_Disposition.OVERWRITE;
                case OpenDisposition.Supersede:
                    return Create_Create_Disposition.SUPERSEDE;
                default:
                    throw new SmbTreeConnectException("Invalid Open Disposition");
            }
        }

        internal static FSCC.FILE_ATTRIBUTE ConvertFileAttributes(FileAttributes attributes)
        {
            FSCC.FILE_ATTRIBUTE fa = FSCC.FILE_ATTRIBUTE.NORMAL;
            if (attributes.HasFlag(FileAttributes.Archive))
            {
                fa |= FSCC.FILE_ATTRIBUTE.ARCHIVE;
            }

            if (attributes.HasFlag(FileAttributes.Compressed))
            {
                fa |= FSCC.FILE_ATTRIBUTE.COMPRESSED;
            }

            if (attributes.HasFlag(FileAttributes.Encrypted))
            {
                fa |= FSCC.FILE_ATTRIBUTE.ENCRYPTED;
            }

            if (attributes.HasFlag(FileAttributes.Hidden))
            {
                fa |= FSCC.FILE_ATTRIBUTE.HIDDEN;
            }

            if (!attributes.HasFlag(FileAttributes.Indexed))
            {
                fa |= FSCC.FILE_ATTRIBUTE.NOT_CONTENT_INDEXED;
            }

            if (attributes.HasFlag(FileAttributes.ReadOnly))
            {
                fa |= FSCC.FILE_ATTRIBUTE.READONLY;
            }

            if (attributes.HasFlag(FileAttributes.System))
            {
                fa |= FSCC.FILE_ATTRIBUTE.SYSTEM;
            }

            return fa;
        }

        internal static FileAttributes ConvertFileAttributes(FSCC.FILE_ATTRIBUTE attributes)
        {
            FileAttributes fa = FileAttributes.Normal;
            if (attributes.HasFlag(FSCC.FILE_ATTRIBUTE.ARCHIVE))
            {
                fa |= FileAttributes.Archive;
            }

            if (attributes.HasFlag(FSCC.FILE_ATTRIBUTE.COMPRESSED))
            {
                fa |= FileAttributes.Compressed;
            }

            if (attributes.HasFlag(FSCC.FILE_ATTRIBUTE.ENCRYPTED))
            {
                fa |= FileAttributes.Encrypted;
            }

            if (attributes.HasFlag(FSCC.FILE_ATTRIBUTE.HIDDEN))
            {
                fa |= FileAttributes.Hidden;
            }

            if (!attributes.HasFlag(FSCC.FILE_ATTRIBUTE.NOT_CONTENT_INDEXED))
            {
                fa |= FileAttributes.Indexed;
            }

            if (attributes.HasFlag(FSCC.FILE_ATTRIBUTE.READONLY))
            {
                fa |= FileAttributes.ReadOnly;
            }

            if (attributes.HasFlag(FSCC.FILE_ATTRIBUTE.SYSTEM))
            {
                fa |= FileAttributes.System;
            }

            return fa;
        }

        internal ulong SendPacket(Packet packet)
        {
            return this.TreeConnect.SendPacket(packet);
        }

        internal Packet ReceivePacket(ulong messageId)
        {
            return this.TreeConnect.ReceivePacket(messageId);
        }

        /*internal struct OperationBucket
        {
            private bool free;
            private byte sequenceNumber;
        }*/
    }
}
