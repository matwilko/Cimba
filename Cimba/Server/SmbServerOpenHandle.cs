namespace Cimba.Server
{
    using System;
    using Cimba.Protocol.External.Microsoft;

    public class SmbServerOpenHandle
    {
        public SmbServerOpenHandle(DateTime creation, DateTime lastAccess, DateTime lastWrite, DateTime change, long fileSize, FileAttributes attributes, string fileName, bool directory)
        {
            this.CreationTime = creation;
            this.LastAccessTime = lastAccess;
            this.LastWriteTime = lastWrite;
            this.ChangeTime = change;
            this.EndofFile = fileSize;
            this.AllocationSize = fileSize;
            this.Attributes = attributes;
            this.IsDirectory = directory;
            this.FileName = fileName;
        }

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

        public bool IsDirectory { get; private set; }

        public DateTime CreationTime { get; private set; }

        public DateTime LastAccessTime { get; private set; }

        public DateTime LastWriteTime { get; private set; }

        public DateTime ChangeTime { get; private set; }

        public long EndofFile { get; private set; }

        public long AllocationSize { get; private set; }

        public FileAttributes Attributes { get; private set; }

        public string FilePath { get; private set; }

        public string FileName { get; private set; }

        internal FSCC.FILE_ATTRIBUTE BinaryAttributes
        {
            get
            {
                return ConvertFileAttributes(this.Attributes) | (this.IsDirectory ? FSCC.FILE_ATTRIBUTE.DIRECTORY : (FSCC.FILE_ATTRIBUTE)0);
            }
        }

        internal static FSCC.FILE_ATTRIBUTE ConvertFileAttributes(FileAttributes attributes)
        {
            FSCC.FILE_ATTRIBUTE fa = (FSCC.FILE_ATTRIBUTE)0;
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
    }
}
