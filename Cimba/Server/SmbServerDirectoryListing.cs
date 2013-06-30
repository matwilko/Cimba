namespace Cimba.Server
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Text;
    using Cimba.Protocol;
    using Cimba.Protocol.External.Microsoft;

    public class SmbServerDirectoryListing
    {
        public SmbServerDirectoryListing(DateTime creation, DateTime lastAccess, DateTime lastWrite, DateTime change, long fileSize, FileAttributes attributes, int extendedAttributesSize, string shortName, string fileName, string filePath)
        {
            this.CreationTime = creation;
            this.LastAccessTime = lastAccess;
            this.LastWriteTime = lastWrite;
            this.ChangeTime = change;
            this.EndofFile = (long)fileSize;
            this.AllocationSize = (long)fileSize;
            this.Attributes = attributes;
            this.IsDirectory = attributes.HasFlag(FileAttributes.Directory);
            this.FileName = fileName;
            this.FilePath = filePath;
            this.EaSize = (uint)extendedAttributesSize;
        }

        public SmbServerDirectoryListing(DirectoryInfo dir)
            : this(dir.CreationTime, dir.LastAccessTime, dir.LastWriteTime, dir.LastWriteTime, 0, dir.Attributes, 0, dir.Name, dir.Name, dir.Parent.FullName)
        {
        }

        public SmbServerDirectoryListing(DirectoryInfo dir, string forceFileName)
            : this(dir.CreationTime, dir.LastAccessTime, dir.LastWriteTime, dir.LastWriteTime, 0, dir.Attributes, 0, dir.Name, forceFileName, dir.Parent.FullName)
        {
        }

        public SmbServerDirectoryListing(FileInfo file)
            : this(file.CreationTime, file.LastAccessTime, file.LastWriteTime, file.LastWriteTime, 0, file.Attributes, 0, file.Name, file.Name, file.Directory.FullName)
        {
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

        internal uint EaSize { get; private set; }

        internal static byte[] Flatten(List<SmbServerDirectoryListing> listings)
        {
            byte[][] bytearrays = new byte[listings.Count][];
            uint totalLength = 0;
            for (int i = 0; i < listings.Count; i++)
            {
                uint nextEntryOffset = (uint)(94 + Encoding.Unicode.GetByteCount(listings[i].FileName));
                totalLength += nextEntryOffset;
                bytearrays[i] = new byte[nextEntryOffset];
                BitConverterLittleEndian.GetBytes(nextEntryOffset).CopyTo(bytearrays[i], 0);
                BitConverterLittleEndian.GetBytes((ulong)listings[i].CreationTime.ToFileTime()).CopyTo(bytearrays[i], 8);
                BitConverterLittleEndian.GetBytes((ulong)listings[i].LastAccessTime.ToFileTime()).CopyTo(bytearrays[i], 16);
                BitConverterLittleEndian.GetBytes((ulong)listings[i].LastWriteTime.ToFileTime()).CopyTo(bytearrays[i], 24);
                BitConverterLittleEndian.GetBytes((ulong)listings[i].ChangeTime.ToFileTime()).CopyTo(bytearrays[i], 32);
                BitConverterLittleEndian.GetBytes((ulong)listings[i].EndofFile).CopyTo(bytearrays[i], 40);
                BitConverterLittleEndian.GetBytes((ulong)listings[i].AllocationSize).CopyTo(bytearrays[i], 48);
                BitConverterLittleEndian.GetBytes((ulong)ConvertFileAttributes(listings[i].Attributes)).CopyTo(bytearrays[i], 56);
                BitConverterLittleEndian.GetBytes((uint)Encoding.Unicode.GetByteCount(listings[i].FileName)).CopyTo(bytearrays[i], 60);
                bytearrays[i][68] = (byte)Encoding.Unicode.GetByteCount(listings[i].FileName);
                Encoding.Unicode.GetBytes(listings[i].FileName).CopyTo(bytearrays[i], 70);
                Encoding.Unicode.GetBytes(listings[i].FileName).CopyTo(bytearrays[i], 94);
            }

            byte[] flat = new byte[totalLength];
            int offset = 0;
            for (int i = 0; i < listings.Count; i++)
            {
                bytearrays[i].CopyTo(flat, offset);
                offset += bytearrays[i].Length;
            }

            return flat;
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

            if (attributes.HasFlag(FileAttributes.NotContentIndexed))
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

            if (attributes.HasFlag(FileAttributes.Directory))
            {
                fa |= FSCC.FILE_ATTRIBUTE.DIRECTORY;
            }

            return fa;
        }
    }
}
