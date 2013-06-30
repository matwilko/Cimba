namespace Cimba
{
    using System;
    using System.Runtime.Serialization;

    [Serializable]
    internal class SmbPacketException : Exception
    {
        internal SmbPacketException()
            : base()
        {
        }

        internal SmbPacketException(string message)
            : base(message)
        {
        }

        internal SmbPacketException(string message, Exception inner)
            : base(message, inner)
        {
        }

        protected SmbPacketException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
