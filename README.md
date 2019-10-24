# ValidationLinkGenerator
A second factor validation link generator for purposes such as confirming emails, resetting passwords. Borrowed from .NET Identity's implementation, so portions are under license from them.

More or less, here's how it works:

The generate method generates a token which is an encrypted concatenation of a purpose, resource ID, and a construct known as a security stamp (a random string). The resource ID represents the 'thing' we are trying to validate. The Microsoft Data Protection API (DPAPI) handles the encryption of these values, and the method returns an opaque string token for use in a verification link.

Validation requires that the user provide a resource ID and their token. We use the resource ID to lookup the corresponding security stamp that was used to generate the one time use link. Then, we can validate the token by using the Data Protection API to decrypt it, checking the purpose matches, the resource ID matches the one provided by the user, and the two security stamps (both the one in the token and the one held server-side for the provided resource ID) match.

# Usage

After binding `IDataProtectorTokenProvider`, you can use the following methods:

## Generate()

This method takes in the following parameters:

- Purpose: This is the purpose for which the token will be used. It's just a user-specified string that you can use to differentiate token use cases. For example, if I wanted to have different tokens for "ConfirmEmail" and "ForgotPassword" on a user with one ID, this purpose field would allow me to do so.

- ResourceId: This is the 'resource' for which the token will be valid (it gets embedded inside). In the case of a forgot password flow, as an example, this'd be something like a UserId. If your use case is confirming another resource via email, it'd be that resource ID.

- SecurityStamp: This is a cryptographically random-generated string, 20 bytes in size. It should be stored alongside the resource being validated by the token, and will live inside the token itself as well. The security stamp is a cryptographically random value which is known only to the server. 

You'll get back a string containing the token to include in your link.

## Validate()

This method takes in the following parameters:

- Token: This is the token that was passed in by the user. We're going to validate it.

- ExpectedPurpose: This is the purpose for which we expect the token to be valid. It should match the one used to generate the token.

- ExpectedResourceId: This is the resource ID for which we think the token is valid. This should be passed in by the user as well. 

- ExpectedSecurityStamp: This is the real security stamp for the resource ID the user passed in. If their token is valid, the security stamp offered by the user in the token and this security stamp should match.

You'll get back a true or false value indicating the validity of the token.


See the unit tests for further examples.