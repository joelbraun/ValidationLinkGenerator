
// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.IO;
using System.Text;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging;

namespace ValidationLinkGenerator
{
    /// <summary>
    /// Provides protection and validation of identity tokens.
    /// </summary>
    /// <typeparam name="TUser">The type used to represent a user.</typeparam>
    public class DataProtectorTokenProvider : IDataProtectorTokenProvider
    {
        // The provider name
        private const string _name = "ValidationTokenProvider";
        // The valid lifespan of the validation token.
        private static readonly TimeSpan _tokenLifespan = TimeSpan.FromDays(1);

        public DataProtectorTokenProvider(IDataProtectionProvider dataProtectionProvider,
                                          ILogger logger)
        {
            if (dataProtectionProvider == null)
            {
                throw new ArgumentNullException(nameof(dataProtectionProvider));
            }

            // Use the Name as the purpose which should usually be distinct from others
            Protector = dataProtectionProvider.CreateProtector(Name ?? "DataProtectorTokenProvider");
            Logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// Gets the <see cref="IDataProtector"/> for this instance.
        /// </summary>
        /// <value>
        /// The <see cref="IDataProtector"/> for this instance.
        /// </value>
        protected IDataProtector Protector { get; private set; }

        /// <summary>
        /// Gets the name of this instance.
        /// </summary>
        /// <value>
        /// The name of this instance.
        /// </value>
        public string Name { get; } = _name;

        /// <summary>
        /// Gets the <see cref="ILogger"/> used to log messages from the provider.
        /// </summary>
        /// <value>
        /// The <see cref="ILogger"/> used to log messages from the provider.
        /// </value>
        public ILogger Logger { get; }

        /// <summary>
        /// Generates a protected token for the specified resourceId.
        /// </summary>
        /// <param name="purpose">The purpose for which the token will be used. A user-specified string that you can use to differentiate token use cases. </param>
        /// <param name="resourceId">The resource Id to which the token corresponds.</param>
        /// <param name="securityStamp">The security stamp to use in generating the token.</param>
        /// <returns></returns>
        public virtual string Generate(string purpose, string resourceId, string securityStamp)
        {
            if (purpose == null)
            {
                throw new ArgumentNullException(nameof(purpose));
            }
            if (resourceId == null)
            {
                throw new ArgumentNullException(nameof(resourceId));
            }
            if (securityStamp == null)
            {
                throw new ArgumentNullException(nameof(securityStamp));
            }

            var ms = new MemoryStream();
            using (var writer = ms.CreateWriter())
            {
                writer.Write(DateTimeOffset.UtcNow);
                writer.Write(resourceId);
                writer.Write(purpose);
                writer.Write(securityStamp);
            }
            var protectedBytes = Protector.Protect(ms.ToArray());
            return Convert.ToBase64String(protectedBytes);
        }

        /// <summary>
        /// Validates the protected <paramref name="token"/> for the specified <paramref name="expectedResourceId"/> is valid.
        /// </summary>
        /// <param name="token">The token to validate.</param>
        /// <param name="expectedPurpose">The purpose for which the token is expected to be used.</param>
        /// <param name="expectedResourceId">The resource ID to which the token corresponds.</param>
        /// <param name="expectedSecurityStamp">The security stamp the token is expected to match.</param>
        /// <returns>True or false indicating the validation result.</returns>
        public virtual bool Validate(string token, string expectedPurpose, string expectedResourceId, string expectedSecurityStamp)
        {
            try
            {
                var unprotectedData = Protector.Unprotect(Convert.FromBase64String(token));
                var ms = new MemoryStream(unprotectedData);
                using (var reader = ms.CreateReader())
                {
                    var creationTime = reader.ReadDateTimeOffset();
                    var expirationTime = creationTime + _tokenLifespan;
                    if (expirationTime < DateTimeOffset.UtcNow)
                    {
                        Logger.InvalidExpirationTime();
                        return false;
                    }

                    var userId = reader.ReadString();
                    if (userId != expectedResourceId)
                    {
                        Logger.UserIdsNotEquals();
                        return false;
                    }

                    var purp = reader.ReadString();
                    if (!string.Equals(purp, expectedPurpose))
                    {
                        Logger.PurposeNotEquals(expectedPurpose, purp);
                        return false;
                    }

                    var stamp = reader.ReadString();
                    if (reader.PeekChar() != -1)
                    {
                        Logger.UnexpectedEndOfInput();
                        return false;
                    }

                    var isEqualsSecurityStamp = stamp == expectedSecurityStamp;
                    if (!isEqualsSecurityStamp)
                    {
                        Logger.SecurityStampNotEquals();
                    }

                    return isEqualsSecurityStamp;
                }
            }
            catch
            {
                // Do not leak exception
                Logger.UnhandledException();
            }

            return false;
        }
    }

    /// <summary>
    /// Utility extensions to streams
    /// </summary>
    internal static class StreamExtensions
    {
        internal static readonly Encoding DefaultEncoding = new UTF8Encoding(false, true);

        public static BinaryReader CreateReader(this Stream stream)
        {
            return new BinaryReader(stream, DefaultEncoding, true);
        }

        public static BinaryWriter CreateWriter(this Stream stream)
        {
            return new BinaryWriter(stream, DefaultEncoding, true);
        }

        public static DateTimeOffset ReadDateTimeOffset(this BinaryReader reader)
        {
            return new DateTimeOffset(reader.ReadInt64(), TimeSpan.Zero);
        }

        public static void Write(this BinaryWriter writer, DateTimeOffset value)
        {
            writer.Write(value.UtcTicks);
        }
    }
}