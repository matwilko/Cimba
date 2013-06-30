namespace Cimba.Server
{
    using Cimba.Protocol;

    public abstract class SmbServerShare
    {
        protected SmbServerShare(
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
        {
            this.IsDfs = isDfs;
            this.CSCFlags = cscFlags;
            this.DoAccessBasedDirectoryEnumeration = doAccessBasedDirectoryEnumeration;
            this.AllowNamespaceCaching = allowNamespaceCaching;
            this.ForceSharedDelete = forceSharedDelete;
            this.RestrictExclusiveOpens = restrictExclusiveOpens;
            this.MaxUses = maxUses;
            this.ForceLevel2Oplock = forceLevel2Oplock;
            this.HashEnabled = hashEnabled;
        }

        public string Name { get; private set; }

        public bool IsDfs { get; private set; }

        public ClientSideCaching CSCFlags { get; private set; }

        public bool DoAccessBasedDirectoryEnumeration { get; private set; }

        public bool AllowNamespaceCaching { get; private set; }

        public bool ForceSharedDelete { get; private set; }

        public bool RestrictExclusiveOpens { get; private set; }

        public string Remark { get; private set; }

        public int MaxUses { get; private set; }

        public int CurrentUses { get; private set; }

        public bool ForceLevel2Oplock { get; private set; }

        public bool HashEnabled { get; private set; }

        internal abstract TreeConnectResponse.ShareType ShareType { get; }

        internal abstract TreeConnectResponse.ShareFlags Flags { get; }

        internal abstract TreeConnectResponse.ShareCapabilities Capabilities { get; }

        internal abstract AccessMask.File_Pipe_Printer MaximalAccess { get; }
    }
}