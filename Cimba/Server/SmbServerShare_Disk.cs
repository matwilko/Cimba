namespace Cimba.Server
{
    using Cimba.Protocol;

    public class SmbServerShare_Disk : SmbServerShare
    {
        public SmbServerShare_Disk(
                                    string shareName,
                                    bool isDfs = false,
                                    ClientSideCaching cscFlags = ClientSideCaching.None,
                                    bool doAccessBasedDirectoryEnumeration = false,
                                    bool allowNamespaceCaching = false,
                                    bool forceSharedDelete = false,
                                    bool restrictExclusiveOpens = false,
                                    int maxUses = 128,
                                    bool forceLevel2Oplock = true,
                                    bool hashEnabled = false)
            : base(shareName, isDfs, cscFlags, doAccessBasedDirectoryEnumeration, allowNamespaceCaching, forceSharedDelete, restrictExclusiveOpens, maxUses, forceLevel2Oplock, hashEnabled)
        {
        }

        internal override TreeConnectResponse.ShareType ShareType
        {
            get
            {
                return TreeConnectResponse.ShareType.DISK;
            }
        }

        internal override TreeConnectResponse.ShareFlags Flags
        {
            get
            {
                TreeConnectResponse.ShareFlags flags = (TreeConnectResponse.ShareFlags)0;
                switch (this.CSCFlags)
                {
                    case ClientSideCaching.Automatic:
                        flags |= TreeConnectResponse.ShareFlags.AUTO_CACHING;
                        break;
                    case ClientSideCaching.Manual:
                        flags |= TreeConnectResponse.ShareFlags.MANUAL_CACHING;
                        break;
                    case ClientSideCaching.None:
                        flags |= TreeConnectResponse.ShareFlags.NO_CACHING;
                        break;
                    case ClientSideCaching.VDO:
                        flags |= TreeConnectResponse.ShareFlags.VDO_CACHING;
                        break;
                }

                if (this.IsDfs)
                {
                    flags |= TreeConnectResponse.ShareFlags.DFS;
                    flags |= TreeConnectResponse.ShareFlags.DFS_ROOT;
                }

                if (this.RestrictExclusiveOpens)
                {
                    flags |= TreeConnectResponse.ShareFlags.RESTRICT_EXLUSIVE_OPENS;
                }

                if (this.ForceSharedDelete)
                {
                    flags |= TreeConnectResponse.ShareFlags.FORCE_SHARED_DELETE;
                }

                if (this.AllowNamespaceCaching)
                {
                    flags |= TreeConnectResponse.ShareFlags.ALLOW_NAMESPACE_CACHING;
                }

                if (this.DoAccessBasedDirectoryEnumeration)
                {
                    flags |= TreeConnectResponse.ShareFlags.ACCESS_BASED_DIRECTORY_ENUM;
                }

                if (this.ForceLevel2Oplock)
                {
                    flags |= TreeConnectResponse.ShareFlags.FORCE_LEVELII_OPLOCK;
                }

                if (this.HashEnabled)
                {
                    flags |= TreeConnectResponse.ShareFlags.ENABLE_HASH;
                }

                return flags;
            }
        }

        internal override TreeConnectResponse.ShareCapabilities Capabilities
        {
            get
            {
                return this.IsDfs ? TreeConnectResponse.ShareCapabilities.CAP_DFS : (TreeConnectResponse.ShareCapabilities)0;
            }
        }

        internal override AccessMask.File_Pipe_Printer MaximalAccess
        {
            get
            {
                return AccessMask.File_Pipe_Printer.GENERIC_ALL;
            }
        }
    }
}
