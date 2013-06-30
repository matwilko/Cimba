namespace Cimba
{
    using System;
    using System.Runtime.Serialization;

    [Serializable]
    public class SmbTreeConnectException : Exception
    {
        internal SmbTreeConnectException()
            : base()
        {
        }

        internal SmbTreeConnectException(string message)
            : base(message)
        {
        }

        internal SmbTreeConnectException(string message, Exception inner)
            : base(message, inner)
        {
        }

        protected SmbTreeConnectException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
