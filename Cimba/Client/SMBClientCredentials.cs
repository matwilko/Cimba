namespace Cimba.Client
{
    public struct SmbClientCredentials
    {
        private string domain;

        private string username;

        private string password;

        public SmbClientCredentials(string domain, string username, string password)
        {
            this.domain = domain;
            this.username = username;
            this.password = password;
        }

        public string Domain
        {
            get
            {
                return this.domain;
            }
        }

        public string Username
        {
            get
            {
                return this.username;
            }
        }

        internal string Password
        {
            get
            {
                return this.password;
            }
        }

        public static bool operator ==(SmbClientCredentials a, SmbClientCredentials b)
        {
            return a.Domain.Equals(b.Domain) && a.Username.Equals(b.Username) && a.Password.Equals(b.Password);
        }

        public static bool operator !=(SmbClientCredentials a, SmbClientCredentials b)
        {
            return !(a == b);
        }

        public override bool Equals(object obj)
        {
            return (obj.GetType() == typeof(SmbClientCredentials)) && (this == (SmbClientCredentials)obj);
        }

        public override int GetHashCode()
        {
            return base.GetHashCode();
        }
    }
}
