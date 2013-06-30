namespace Cimba
{
    using System.Collections.Generic;
    using System.Net;

    public class IPEndPointComparer : EqualityComparer<IPEndPoint>
    {
        public override bool Equals(IPEndPoint x, IPEndPoint y)
        {
            return x.Address.Equals(y.Address) && x.Port.Equals(y.Port);
        }

        public override int GetHashCode(IPEndPoint obj)
        {
            return obj.GetHashCode();
        }
    }
}
