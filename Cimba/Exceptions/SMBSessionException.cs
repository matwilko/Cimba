namespace Cimba
{
    using System;
    using System.Runtime.Serialization;

    [Serializable]
    public class SmbSessionException : Exception
    {
        internal SmbSessionException()
            : base()
        {
        }

        internal SmbSessionException(string message)
            : base(message)
        {
        }

        internal SmbSessionException(string message, Exception inner)
            : base(message, inner)
        {
        }

        protected SmbSessionException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
