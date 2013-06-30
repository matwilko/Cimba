namespace Cimba.Client
{
    using System;
    using System.Collections.Generic;

    public class SmbClientFile
    {
        public readonly SmbClientTreeConnect TreeConnect;

        private List<SmbClientOpen> openTable = new List<SmbClientOpen>();

        private Guid leaseKey; // Uniquely identifies this file's entry in the GlobalFileTable

        ////LeaseState - the lease level state granted for this file by the server

        internal SmbClientFile(SmbClientOpen open)
        {
            this.openTable.Add(open);
            this.leaseKey = Guid.NewGuid();
            this.TreeConnect = open.TreeConnect;
            this.FileName = open.FileName;
        }

        internal string FileName { get; set; }

        internal void AddOpen(SmbClientOpen open)
        {
            this.openTable.Add(open);
        }

        internal void RemoveOpen(SmbClientOpen open)
        {
            this.openTable.Remove(open);
            if (this.openTable.Count == 0)
            {
                this.TreeConnect.Session.Connection.RemoveFile(this);
            }
        }
    }
}
