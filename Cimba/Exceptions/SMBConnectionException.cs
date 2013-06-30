namespace Cimba
{
    using System;
    using System.Runtime.Serialization;

    [Serializable]
    public class SmbConnectionException : Exception
    {
        internal SmbConnectionException()
            : base()
        {
        }

        internal SmbConnectionException(string message)
            : base(message)
        {
        }

        internal SmbConnectionException(string message, Exception inner)
            : base(message, inner)
        {
        }

        protected SmbConnectionException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
