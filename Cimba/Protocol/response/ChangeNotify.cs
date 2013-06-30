namespace Cimba.Protocol
{
    using System;
    using System.Collections.Generic;
    using System.IO;

    internal class ChangeNotifyResponse : Packet
    {
        internal List<FILE_NOTIFY_INFORMATION> FileNotifyInformation { get; set; }

        internal static ChangeNotifyResponse Read(MemoryStream stream)
        {
            if (BitConverterLE.ToUShort(stream) != 9)
            {
                throw new SmbPacketException("Invalid ChangeNotifyResponse");
            }

            ChangeNotifyResponse packet = new ChangeNotifyResponse();

            // OutputBufferOffset (2 bytes)
            ushort outputBufferOffset = BitConverterLE.ToUShort(stream);

            // OutputBufferLength (4 bytes)
            uint outputBufferLength = BitConverterLE.ToUInt(stream);

            // Buffer (variable)
            byte[] buffer = new byte[outputBufferLength];
            stream.Read(buffer, outputBufferOffset - Packet.HeaderLength, (int)outputBufferLength);
            packet.FileNotifyInformation = FILE_NOTIFY_INFORMATION.ReadList(buffer);

            return packet;
        }

        protected override byte[] Generate()
        {
            throw new NotImplementedException();
        }
    }
}
