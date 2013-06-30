namespace Cimba.Server
{
    using System;
    using System.Collections.Generic;
    using Cimba.Protocol;

    public delegate SmbServerOpenHandle OpenDelegate(SmbServerTreeConnect treeConnect, string fileName, CreateDisposition disposition);

    public delegate List<SmbServerDirectoryListing> ListDirectoryDelegate(string dirName, string searchPattern);

    public class SmbServerOpen
    {
        internal SmbServerOpen(SmbServerTreeConnect treeConnect, CreateRequest request, OpenDelegate open)
        {
            this.TreeConnect = treeConnect;

            CreateDisposition dispos = CreateDisposition.OpenOrCreate;
            switch (request.CreateDisposition)
            {
                case Create_Create_Disposition.CREATE:
                    dispos = CreateDisposition.Create;
                    break;
                case Create_Create_Disposition.OPEN:
                    dispos = CreateDisposition.Open;
                    break;
                case Create_Create_Disposition.OPEN_IF:
                    dispos = CreateDisposition.OpenOrCreate;
                    break;
                case Create_Create_Disposition.OVERWRITE:
                    dispos = CreateDisposition.Overwrite;
                    break;
                case Create_Create_Disposition.OVERWRITE_IF:
                    dispos = CreateDisposition.OverwriteOrCreate;
                    break;
                case Create_Create_Disposition.SUPERSEDE:
                    dispos = CreateDisposition.Supersede;
                    break;
            }

            this.Handle = open(treeConnect, request.Filename, dispos);
            byte[] fileid = new byte[16];
            (new Random()).NextBytes(fileid);
            this.FileId = new FILE_ID(fileid);

            CreateResponse response = new CreateResponse();
            response.OplockLevel = Create_Oplock_Level.NONE;
            response.CreateAction = CreateResponse.Create_Action.OPENED;
            response.CreationTime = (ulong)this.Handle.CreationTime.ToFileTime();
            response.LastAccessTime = (ulong)this.Handle.LastAccessTime.ToFileTime();
            response.LastWriteTime = (ulong)this.Handle.LastWriteTime.ToFileTime();
            response.ChangeTime = (ulong)this.Handle.ChangeTime.ToFileTime();
            response.AllocationSize = (ulong)this.Handle.AllocationSize;
            response.EndOfFile = (ulong)this.Handle.EndofFile;
            response.FileAttributes = this.Handle.BinaryAttributes;
            response.FileId = this.FileId;
            response.CreateContexts = new List<Create_Create_Context>();

            this.TreeConnect.SendPacket(request, response);
        }

        public SmbServerTreeConnect TreeConnect { get; private set; }

        internal SmbServerOpenHandle Handle { get; private set; }

        internal FILE_ID FileId { get; private set; }
        
        internal bool DirectoryEnumed { get; set; }
    }
}
