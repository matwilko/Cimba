namespace Cimba
{
    using System;
    using System.Runtime.Serialization;
    using Cimba.Protocol;

    [Serializable]
    internal class SmbProtocolException : Exception
    {
        internal SmbProtocolException()
            : base()
        {
        }

        internal SmbProtocolException(string message)
            : base(message)
        {
        }

        internal SmbProtocolException(string message, Exception inner)
            : base(message, inner)
        {
        }

        internal SmbProtocolException(byte[] errorData, uint status, Packet origpacket)
            : base()
        {
            this.ErrorData = errorData;
        }

        protected SmbProtocolException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }

        internal byte[] ErrorData { get; private set; }

        internal uint Status { get; private set; }

        internal Packet OrigPacket { get; private set; }
    }
}
