namespace ValidationLinkGenerator
{
    public interface IDataProtectorTokenProvider
    {
        string Generate(string purpose, string resourceId, string securityStamp);

        bool Validate(string token, string expectedPurpose, string expectedResourceId, string expectedSecurityStamp);
    }
}