using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ValidationLinkGenerator;
using Xunit;

namespace UnitTests
{
    public class ValidationLinkGeneratorTests
    {
        private readonly IDataProtectorTokenProvider _dataProtectorTokenProvider;

        private const string _testPurpose = "purpose";
        private const string _resourceId = "bfaf2b0b-6f2c-4e3e-b38f-fe3c32538b32";

        public ValidationLinkGeneratorTests()
        {
            // Add services
            var serviceCollection = new ServiceCollection();
            // Microsoft DPAPI
            serviceCollection.AddDataProtection();
            // logging
            var loggerFactory = LoggerFactory.Create(builder =>
            {
                builder.AddConsole();
            });
            serviceCollection.AddSingleton<ILogger>(loggerFactory.CreateLogger<IDataProtectorTokenProvider>());
            // The actual token generation service
            serviceCollection.AddTransient<IDataProtectorTokenProvider, DataProtectorTokenProvider>();

            var serviceProvider = serviceCollection.BuildServiceProvider();
            _dataProtectorTokenProvider = serviceProvider.GetService<IDataProtectorTokenProvider>();
        }

        [Fact]
        public void TokenValid()
        {
            var securityStamp = SecurityStampGenerator.NewSecurityStamp();

            var token = _dataProtectorTokenProvider.Generate(_testPurpose, _resourceId, securityStamp);
            var result = _dataProtectorTokenProvider.Validate(token, _testPurpose, _resourceId, securityStamp);

            Assert.True(result);
        }

        [Fact]
        public void TokenInvalid_TokenEmpty()
        {
            var securityStamp = SecurityStampGenerator.NewSecurityStamp();

            var result = _dataProtectorTokenProvider.Validate(string.Empty, _testPurpose, _resourceId, securityStamp);

            Assert.False(result);
        }

        [Fact]
        public void TokenInvalid_PurposeMismatch()
        {
            var securityStamp = SecurityStampGenerator.NewSecurityStamp();

            var token = _dataProtectorTokenProvider.Generate(_testPurpose, _resourceId, securityStamp);
            var result = _dataProtectorTokenProvider.Validate(token, "invalidPurpose", _resourceId, securityStamp);

            Assert.False(result);
        }

        [Fact]
        public void TokenInvalid_StampMismatch()
        {
            var securityStamp = SecurityStampGenerator.NewSecurityStamp();
            var wrongStamp = SecurityStampGenerator.NewSecurityStamp();

            var token = _dataProtectorTokenProvider.Generate(_testPurpose, _resourceId, securityStamp);
            var result = _dataProtectorTokenProvider.Validate(token, _testPurpose, _resourceId, wrongStamp);

            Assert.False(result);
        }

        [Fact]
        public void TokenInvalid_ResourceIdMismatch()
        {
            // note: this case isn't likely to happen, because with an invalid resource id, you'd look up the wrong
            // stamp to validate with anyway.
            var securityStamp = SecurityStampGenerator.NewSecurityStamp();

            var token = _dataProtectorTokenProvider.Generate(_testPurpose, _resourceId, securityStamp);
            var result = _dataProtectorTokenProvider.Validate(token, _testPurpose, "invalidResource", securityStamp);

            Assert.False(result);
        }
    }
}
