namespace Cimba.Protocol.External.Microsoft
{
    using System;
    using System.IO;
    using System.Security.Cryptography;
    using Cimba.Client;
    using Cimba.Server;
    using Org.BouncyCastle.Crypto.Engines;
    using Org.BouncyCastle.Crypto.Parameters;

    internal static class SPNG
    {
        private static uint[][] supportedmechanisms = new uint[][]
        {
            new uint[] { 1, 3, 6, 1, 4, 1, 311, 2, 2, 10 }
        };

        private static byte[] clientmechList;

        private enum NegState : int
        {
            accept_completed = 0,
            accept_incomplete = 1,
            reject = 2,
            request_mic = 3
        }

        internal static byte[] ReadNegTokenInit2(byte[] securityblob)
        {
            if (securityblob.Length != 0)
            {
                // Read GSSAPI InitialContextToken
                MemoryStream ict = new MemoryStream(DecodeDER.DecodeSequence(new MemoryStream(securityblob), 0x00, ASN1.IdentClass.Application, ASN1.IdentType.Constructed));
                uint[] ictoid = DecodeDER.DecodeOID(ict);
                byte[] innerContextToken = new byte[(int)(ict.Length - ict.Position)];
                ict.Read(innerContextToken, 0, (int)(ict.Length - ict.Position));
                if (!ASN1.MatchOID(new uint[] { 1, 3, 6, 1, 5, 5, 2 }, ictoid))
                {
                    throw new NotImplementedException("Expected SPNEGO");
                }

                MemoryStream negotiationToken = new MemoryStream(DecodeDER.DecodeSequence(new MemoryStream(innerContextToken), 0x00, ASN1.IdentClass.ContextSpecific));

                MemoryStream negTokenInit = new MemoryStream(DecodeDER.DecodeSequence(negotiationToken));

                MemoryStream mechTypeList = new MemoryStream(DecodeDER.DecodeSequence(negTokenInit, 0x00, ASN1.IdentClass.ContextSpecific));

                MemoryStream mechTypes = new MemoryStream(DecodeDER.DecodeSequence(mechTypeList));

                ////uint[] chosenMech;
                bool chosen = false;
                for (int i = 0; mechTypes.Position != mechTypes.Length; i++)
                {
                    uint[] oid = DecodeDER.DecodeOID(mechTypes);
                    for (int j = 0; j < supportedmechanisms.Length; j++)
                    {
                        if (ASN1.MatchOID(supportedmechanisms[j], oid))
                        {
                            ////chosenMech = supportedmechanisms[j];
                            chosen = true;
                            break;
                        }
                    }
                }

                if (!chosen)
                {
                    // TODO: Add proper exception
                    throw new NotImplementedException("No common mechanism");
                }
            }

            ////return BuildNegTokenInit(NTLM.NEGOTIATE_MESSAGE("Matt-Laptop"));
            return BuildNegTokenInit(NTLM2.NEGOTIATE_MESSAGE());
        }

        internal static byte[] GenerateNegTokenInit2()
        {
            byte[] supportedmechsflat = new byte[0];
            foreach (uint[] mech in supportedmechanisms)
            {
                byte[] mechBytes = EncodeDER.EncodeOID(mech);
                byte[] newList = new byte[supportedmechsflat.Length + mechBytes.Length];
                supportedmechsflat.CopyTo(newList, 0);
                mechBytes.CopyTo(newList, supportedmechsflat.Length);
                supportedmechsflat = mechBytes;
            }

            byte[] mechTypes = EncodeDER.EncodeSequence(supportedmechsflat);
            byte[] mechTypeList = EncodeDER.EncodeSequence(mechTypes, 0x00, ASN1.IdentClass.ContextSpecific);
            byte[] negTokenInit = EncodeDER.EncodeSequence(mechTypeList);
            byte[] negotiationToken = EncodeDER.EncodeSequence(negTokenInit, 0x00, ASN1.IdentClass.ContextSpecific);
            byte[] ictOID = EncodeDER.EncodeOID(new uint[] { 1, 3, 6, 1, 5, 5, 2 });
            byte[] negTokenandOID = new byte[negotiationToken.Length + ictOID.Length];
            ictOID.CopyTo(negTokenandOID, 0);
            negotiationToken.CopyTo(negTokenandOID, ictOID.Length);
            byte[] initialContextToken = EncodeDER.EncodeSequence(negTokenandOID, 0x00, ASN1.IdentClass.Application);
            return initialContextToken;
        }

        internal static Tuple<byte[], byte[]> ReadFirstNegTokenResp(byte[] securityblob, SmbClientCredentials cred)
        {
            MemoryStream negotiationToken = new MemoryStream(DecodeDER.DecodeSequence(new MemoryStream(securityblob), 0x01, ASN1.IdentClass.ContextSpecific));

            MemoryStream negTokenResp = new MemoryStream(DecodeDER.DecodeSequence(negotiationToken));

            MemoryStream negstate_outer = new MemoryStream(DecodeDER.DecodeSequence(negTokenResp, 0x00, ASN1.IdentClass.ContextSpecific));
            NegState negState = (NegState)DecodeDER.DecodeInteger(negstate_outer, 0x0A);

            ////MemoryStream supportedMech_outer = new MemoryStream(   );
            DecodeDER.DecodeSequence(negTokenResp, 0x01, ASN1.IdentClass.ContextSpecific);
            ////uint[] supportedMech = DecodeDER.DecodeOID(supportedMech_outer);

            MemoryStream responseToken_outer = new MemoryStream(DecodeDER.DecodeSequence(negTokenResp, 0x02, ASN1.IdentClass.ContextSpecific));
            byte[] responseToken = DecodeDER.DecodeOctetString(responseToken_outer);

            if (negState == NegState.reject)
            {
                throw new SmbConnectionException("SPNEGO Failed.");
            }
            else if (negState == NegState.accept_completed)
            {
                return new Tuple<byte[], byte[]>(new byte[0], new byte[0]);
            }
            else if (negState == NegState.accept_incomplete)
            {
                Tuple<bool, ulong, byte[]> challenge = NTLM2.CHALLENGE_MESSAGE(responseToken);
                if (challenge.Item1)
                {
                    ulong serverChallenge = challenge.Item2;
                    byte[] targetInfo = challenge.Item3;
                    return WrapNTLMToken(serverChallenge, targetInfo, cred, responseToken);
                }
                else
                {
                    throw new SmbProtocolException("Invalid NTLM Challenge");
                }
            }
            else
            {
                throw new NotImplementedException();
            }
        }

        internal static byte[] ReadNegTokenInit(byte[] returnsecurityblob)
        {
            MemoryStream blob = new MemoryStream(returnsecurityblob);
            if (returnsecurityblob[0] == 0x60)
            {
                // GSSAPI outer shell included!
                MemoryStream gssapi = new MemoryStream(DecodeDER.DecodeSequence(blob, 0x00, ASN1.IdentClass.Application));
                DecodeDER.DecodeOID(gssapi);
                blob = gssapi;
            }

            blob = new MemoryStream(DecodeDER.DecodeSequence(blob, 0x00, ASN1.IdentClass.ContextSpecific));
            try
            {
                DecodeDER.DecodeSequence(blob, 0x00, ASN1.IdentClass.ContextSpecific);
            }
            catch (DecodeDER.WrongFieldException)
            {
            }
            catch (NotImplementedException)
            {
            }

            try
            {
                DecodeDER.DecodeSequence(blob, 0x01, ASN1.IdentClass.ContextSpecific);
            }
            catch (DecodeDER.WrongFieldException)
            {
            }
            catch (NotImplementedException)
            {
            }

            MemoryStream negTokenInit = new MemoryStream(DecodeDER.DecodeSequence(blob));
            byte[] mechTypeList = DecodeDER.DecodeSequence(negTokenInit, 0x00, ASN1.IdentClass.ContextSpecific);
            SPNG.clientmechList = mechTypeList;
            byte[] mechToken = DecodeDER.DecodeSequence(negTokenInit, 0x02, ASN1.IdentClass.ContextSpecific);
            byte[] securityToken = DecodeDER.DecodeOctetString(new MemoryStream(mechToken));
            MemoryStream sequenceOfMechType = new MemoryStream(DecodeDER.DecodeSequence(new MemoryStream(mechTypeList)));
            bool correctMech = false;
            uint[] mechMatch = new uint[] { 1, 3, 6, 1, 4, 1, 311, 2, 2, 10 };
            while (sequenceOfMechType.Position != sequenceOfMechType.Length)
            {
                if (ASN1.MatchOID(mechMatch, DecodeDER.DecodeOID(sequenceOfMechType)))
                {
                    correctMech = true;
                    break;
                }
            }

            if (!correctMech)
            {
                throw new SmbProtocolException("Could not negotiate SPNEGO");
            }
            else
            {
                if (!NTLM2.NEGOTIATE_MESSAGE(securityToken))
                {
                    throw new SmbProtocolException("Could not negotiate NTLM");
                }
            }

            return mechTypeList;
        }

        internal static byte[] GenerateFirstNegTokenResp(ulong serverChallenge)
        {
            byte[] ntlmToken = NTLM2.CHALLENGE_MESSAGE(serverChallenge, SmbServer.ServerName);

            byte[] responseToken_outer = EncodeDER.EncodeSequence(EncodeDER.EncodeOctetstring(ntlmToken), 0x02, ASN1.IdentClass.ContextSpecific);
            byte[] supportedMech = EncodeDER.EncodeSequence(EncodeDER.EncodeOID(supportedmechanisms[0]), 0x01, ASN1.IdentClass.ContextSpecific);
            byte[] negstate_outer = EncodeDER.EncodeSequence(EncodeDER.EncodeInteger((int)NegState.accept_incomplete, 0x0A), 0x00, ASN1.IdentClass.ContextSpecific);
            byte[] lastThreeTogether = new byte[responseToken_outer.Length + supportedMech.Length + negstate_outer.Length];
            negstate_outer.CopyTo(lastThreeTogether, 0);
            supportedMech.CopyTo(lastThreeTogether, negstate_outer.Length);
            responseToken_outer.CopyTo(lastThreeTogether, negstate_outer.Length + supportedMech.Length);
            byte[] negTokenResp = EncodeDER.EncodeSequence(lastThreeTogether);
            byte[] negotiationToken = EncodeDER.EncodeSequence(negTokenResp, 0x01, ASN1.IdentClass.ContextSpecific);

            return negotiationToken;
        }

        internal static Tuple<bool, byte[], byte[]> ReadFinalToken(byte[] buffer, ulong challenge, AuthenticateClientDelegate auth, byte[] mechList)
        {
            byte[] negTokenTarg = DecodeDER.DecodeSequence(new MemoryStream(buffer), 0x01, ASN1.IdentClass.ContextSpecific);
            byte[] negTokenRespbytes = DecodeDER.DecodeSequence(new MemoryStream(negTokenTarg));

            MemoryStream negTokenResp = new MemoryStream(negTokenRespbytes);
            try
            {
                DecodeDER.DecodeSequence(negTokenResp, 0x00, ASN1.IdentClass.ContextSpecific);
            }
            catch (DecodeDER.WrongFieldException)
            {
            }

            try
            {
                DecodeDER.DecodeSequence(negTokenResp, 0x01, ASN1.IdentClass.ContextSpecific);
            }
            catch (DecodeDER.WrongFieldException)
            {
            }

            byte[] responseToken = DecodeDER.DecodeOctetString(new MemoryStream(DecodeDER.DecodeSequence(negTokenResp, 0x02, ASN1.IdentClass.ContextSpecific)));

            Tuple<bool, byte[]> ntlm = NTLM2.AUTHENTICATE_MESSAGE(responseToken, challenge, SmbServer.ServerName, auth);
            if (ntlm.Item1)
            {
                byte[] negState = EncodeDER.EncodeSequence(EncodeDER.EncodeInteger((int)NegState.accept_completed, 0x0A), 0x00, ASN1.IdentClass.ContextSpecific);

                byte[] supportedmechsflat = new byte[0];
                foreach (uint[] mech in supportedmechanisms)
                {
                    byte[] mechBytes = EncodeDER.EncodeOID(mech);
                    byte[] newList = new byte[supportedmechsflat.Length + mechBytes.Length];
                    supportedmechsflat.CopyTo(newList, 0);
                    mechBytes.CopyTo(newList, supportedmechsflat.Length);
                    supportedmechsflat = mechBytes;
                }

                byte[] mechListMIC = MIC(ntlm.Item2, EncodeDER.EncodeSequence(supportedmechsflat), false);

                byte[] mechListMIC_outer = EncodeDER.EncodeSequence(EncodeDER.EncodeOctetstring(mechListMIC), 0x03, ASN1.IdentClass.ContextSpecific);
                ////byte[] mechListMIC_outer = new byte[0];

                Console.WriteLine("Calculated client mechListMIC: " + BitConverter.ToString(MIC(ntlm.Item2, SPNG.clientmechList, true)));
                Console.WriteLine("Calculated server mechListMIC: " + BitConverter.ToString(MIC(ntlm.Item2, EncodeDER.EncodeSequence(supportedmechsflat), false)));

                byte[] final_inner = new byte[negState.Length + mechListMIC_outer.Length];
                negState.CopyTo(final_inner, 0);
                mechListMIC_outer.CopyTo(final_inner, negState.Length);
                byte[] returnNegTokenResp = EncodeDER.EncodeSequence(EncodeDER.EncodeSequence(final_inner), 0x01, ASN1.IdentClass.ContextSpecific);
                return new Tuple<bool, byte[], byte[]>(true, returnNegTokenResp, ntlm.Item2);
            }
            else
            {
                byte[] negState = EncodeDER.EncodeSequence(EncodeDER.EncodeInteger((int)NegState.reject), 0x00, ASN1.IdentClass.ContextSpecific);
                byte[] returnNegTokenResp = EncodeDER.EncodeSequence(EncodeDER.EncodeSequence(negState), 0x01, ASN1.IdentClass.ContextSpecific);
                return new Tuple<bool, byte[], byte[]>(false, returnNegTokenResp, new byte[0]);
            }
        }

        private static byte[] BuildNegTokenInit(byte[] returnsecurityblob)
        {
            byte[][] mechoids = new byte[supportedmechanisms.Length][];
            int totallength = 0;
            for (int i = 0; i < supportedmechanisms.Length; i++)
            {
                mechoids[i] = EncodeDER.EncodeOID(supportedmechanisms[i]);
                totallength += mechoids[i].Length;
            }

            byte[] mechoids_flat = new byte[totallength];
            for (int i = 0; i < mechoids.Length; i++)
            {
                mechoids[i].CopyTo(mechoids_flat, mechoids_flat.Length - totallength);
                totallength -= mechoids[i].Length;
            }

            byte[] sequenceOfMechType = EncodeDER.EncodeSequence(mechoids_flat);
            byte[] mechTypeList = EncodeDER.EncodeSequence(sequenceOfMechType, 0x00, ASN1.IdentClass.ContextSpecific);

            byte[] secblob_octetstring = EncodeDER.EncodeOctetstring(returnsecurityblob);
            byte[] mechToken = EncodeDER.EncodeSequence(secblob_octetstring, 0x02, ASN1.IdentClass.ContextSpecific);

            byte[] completeNTI = new byte[mechTypeList.Length + mechToken.Length];
            mechTypeList.CopyTo(completeNTI, 0);
            mechToken.CopyTo(completeNTI, mechTypeList.Length);
            byte[] negTokenInit = EncodeDER.EncodeSequence(completeNTI);

            byte[] negotiationToken = EncodeDER.EncodeSequence(negTokenInit, 0x00, ASN1.IdentClass.ContextSpecific);

            return negotiationToken;
        }

        private static Tuple<byte[], byte[]> WrapNTLMToken(ulong serverChallenge, byte[] targetInfo, SmbClientCredentials cred, byte[] challenge)
        {
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            byte[] sessionKey = new byte[16];
            rng.GetBytes(sessionKey);

            byte[] auth_mess = NTLM2.AUTHENTICATE_MESSAGE(serverChallenge, targetInfo, sessionKey, cred, challenge);

            byte[] supportedmechsflat = new byte[0];
            foreach (uint[] mech in supportedmechanisms)
            {
                byte[] mechBytes = EncodeDER.EncodeOID(mech);
                byte[] newList = new byte[supportedmechsflat.Length + mechBytes.Length];
                supportedmechsflat.CopyTo(newList, 0);
                mechBytes.CopyTo(newList, supportedmechsflat.Length);
                supportedmechsflat = mechBytes;
            }

            byte[] mechTypes = EncodeDER.EncodeSequence(supportedmechsflat);

            HMACMD5 hmacmd5 = new HMACMD5(sessionKey);
            byte[] mechTypesHash = hmacmd5.ComputeHash(mechTypes);
            byte[] mechListMIC = new byte[16];
            BitConverterLE.GetBytes((uint)1).CopyTo(mechListMIC, 0);
            Array.Copy(mechTypesHash, 0, mechListMIC, 4, 8);

            byte[] responseToken = EncodeDER.EncodeSequence(EncodeDER.EncodeOctetstring(auth_mess), 0x02, ASN1.IdentClass.ContextSpecific);
            byte[] mechListMIC_outer = EncodeDER.EncodeSequence(EncodeDER.EncodeOctetstring(mechListMIC), 0x03, ASN1.IdentClass.ContextSpecific);
            byte[] negState = new byte[0];
            byte[] negTokenResp_bytes = new byte[responseToken.Length + negState.Length + mechListMIC_outer.Length];
            negState.CopyTo(negTokenResp_bytes, 0);
            responseToken.CopyTo(negTokenResp_bytes, negState.Length);
            mechListMIC_outer.CopyTo(negTokenResp_bytes, negState.Length + responseToken.Length);
            byte[] negTokenResp = EncodeDER.EncodeSequence(negTokenResp_bytes);
            return new Tuple<byte[], byte[]>(EncodeDER.EncodeSequence(negTokenResp, 0x01, ASN1.IdentClass.ContextSpecific), sessionKey);
        }

        private static byte[] MIC(byte[] key, byte[] data, bool client)
        {
            byte[] dataconcat = new byte[4 + data.Length];
            data.CopyTo(dataconcat, 4);
            HMACMD5 hmacmd5 = new HMACMD5(NTLM2.SigningKey(key, client));
            byte[] mechTypesHash = hmacmd5.ComputeHash(dataconcat);

            RC4Engine rc4 = new RC4Engine();
            rc4.Init(true, new KeyParameter(NTLM2.SealingKey(key, client)));
            byte[] checksum = new byte[16];
            rc4.ProcessBytes(mechTypesHash, 0, 16, checksum, 0);

            byte[] mechListMIC = new byte[16];
            BitConverterLE.GetBytes((uint)1).CopyTo(mechListMIC, 0);
            Array.Copy(checksum, 0, mechListMIC, 4, 8);
            return mechListMIC;
        }
    }
}