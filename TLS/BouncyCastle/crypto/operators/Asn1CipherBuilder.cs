#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using System;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Operators
{
    public class Asn1CipherBuilderWithKey
        : ICipherBuilderWithKey
    {
        private readonly KeyParameter m_encKey;
        private AlgorithmIdentifier m_algID;

        public Asn1CipherBuilderWithKey(DerObjectIdentifier encryptionOID, int keySize, SecureRandom random)
        {
            random = CryptoServicesRegistrar.GetSecureRandom(random);

            CipherKeyGenerator keyGen = CipherKeyGeneratorFactory.CreateKeyGenerator(encryptionOID, random);

            m_encKey = keyGen.GenerateKeyParameter();
            m_algID = AlgorithmIdentifierFactory.GenerateEncryptionAlgID(encryptionOID, m_encKey.KeyLength * 8, random);
        }

        public object AlgorithmDetails => m_algID;

        public int GetMaxOutputSize(int inputLen) => throw new NotImplementedException();

        public ICipher BuildCipher(Stream stream)
        {
            object cipher = CipherFactory.CreateContentCipher(true, m_encKey, m_algID);

            //
            // BufferedBlockCipher
            // IStreamCipher
            //

            if (cipher is IStreamCipher streamCipher)
            {
                cipher = new BufferedStreamCipher(streamCipher);
            }

            if (stream == null)
            {
                stream = new MemoryStream();
            }

            return new BufferedCipherWrapper((IBufferedCipher)cipher, stream);
        }

        public ICipherParameters Key => m_encKey;
    }

    public class BufferedCipherWrapper
        : ICipher
    {
        private readonly IBufferedCipher m_bufferedCipher;
        private readonly CipherStream m_stream;

        public BufferedCipherWrapper(IBufferedCipher bufferedCipher, Stream source)
        {
            m_bufferedCipher = bufferedCipher;
            m_stream = new CipherStream(source, bufferedCipher, bufferedCipher);
        }

        public int GetMaxOutputSize(int inputLen) => m_bufferedCipher.GetOutputSize(inputLen);

        public int GetUpdateOutputSize(int inputLen) => m_bufferedCipher.GetUpdateOutputSize(inputLen);

        public Stream Stream => m_stream;
    }
}
