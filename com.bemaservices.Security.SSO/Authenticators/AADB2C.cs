using IdentityModel;
using IdentityModel.Client;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Rock;
using Rock.Attribute;
using Rock.Data;
using Rock.Model;
using Rock.Oidc.Client;
using Rock.Security;
using Rock.Security.Authentication;
using Rock.Security.Authentication.ExternalRedirectAuthentication;
using Rock.Web.Cache;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.Composition;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Web;

namespace com.bemaservices.Security.SSO.Authenticators
{
    /// <summary>
    /// Authenticates a user using Azure Active Directory B2C
    /// </summary>
    [Description("Azure Active Directory B2C Authentication Provider")]
    [Export(typeof(AuthenticationComponent))]
    [ExportMetadata("ComponentName", "AAD B2C")]

    [UrlLinkField("AAD B2C OpenID Connect Metadata Document URI", "URI for the AADB2C OpenID Connect metadatadocument for your user flow.", true, "", "", 1, AttributeKey.OpenIdConnectMetdataURI)]
    [TextField("Client Id", "This is the Client Id you will obtain from your Azure App Registration on the Overview page.", true, "", "", 2, AttributeKey.ClientId)]
    [TextField("Client Secret", "This is the Client Secret you will obtain from your Azure App Registration on the Certificates & Secrets page.", true, "", "", 3, AttributeKey.ClientSecret)]
    [BooleanField("Satisfies MFA Requirement", "Indicates that your configuration of Azure AD B2C satisfies the MFA requirement for Rock Protection Profiles who sign in using an AADB2C account.", false, "", 4, AttributeKey.SatisfiesMFARequirement)]
    [BooleanField("Enable Debug Mode", "Enabling this will generate exceptions at each point of the authentication process. This is very useful for troubleshooting.", false, "", 5, AttributeKey.EnableDebugMode)]
    public class AADB2C : AuthenticationComponent, IExternalRedirectAuthentication
    {

        # region Constants

        private const string EXCEPTION_DEBUG_TEXT = "Azure AD B2C Debug";

        private const string AADB2C_SHORT_DESCRIPTOR = "AADB2C";

        # endregion

        # region Key Classes

        /// <summary>
        /// Attribute Keys for AADB2C settings
        /// </summary>
        public static class AttributeKey
        {

            /// <summary>
            /// The OpenId connect metadata document URI
            /// </summary>
            public const string OpenIdConnectMetdataURI = "OIDCMetadataURI";

            /// <summary>
            /// The Client Id
            /// </summary>
            public const string ClientId = "ClientId";

            /// <summary>
            /// The Client Secret
            /// </summary>
            public const string ClientSecret = "ClientSecret";

            /// <summary>
            /// Indicates whether or not AADB2C logins satisfy MFA requirements for protection profiles requiring MFA.
            /// </summary>
            public const string SatisfiesMFARequirement = "SatisfiesMFARequirement";

            /// <summary>
            /// Specify whether or not debug mode should be enabled (additional exceptions logged)
            /// </summary>
            public const string EnableDebugMode = "EnableDebugMode";

        }

        /// <summary>
        /// Cookie names for AADB2C auth.
        /// </summary>
        public static class CookieKey
        {

            /// <summary>
            /// The monce cookie name.
            /// </summary>
            public const string Nonce = "aadb2c-nonce";

            /// <summary>
            /// The state cookie name.
            /// </summary>
            public const string State = "aadb2c-state";

            /// <summary>
            /// The return url cookie name.
            /// </summary>
            public const string ReturnUrl = "aadbc2-returnurl";

        }

        /// <summary>
        /// Page parameter names for AADB2C auth.
        /// </summary>
        public static class ParameterKey
        {

            /// <summary>
            /// The return url parameter.
            /// </summary>
            public const string ReturnUrl = "returnurl";

            /// <summary>
            /// The code parameter.
            /// </summary>
            public const string Code = "code";

            /// <summary>
            /// The state parameter.
            /// </summary>
            public const string State = "state";

        }

        /// <summary>
        /// Keys for non-standard claim structure returned by AADB2C OIDC.
        /// </summary>
        public static class ClaimsKey
        {
            
            /// <summary>
            /// The emails claim, since AADB2C returns an array instead of single email by default (so we can't use the standard claim name)
            /// </summary>
            public const string Emails = "emails";

        }

        # endregion

        # region Metadata Helper Methods

        /// <summary>
        /// Gets the type of the service.
        /// </summary>
        /// <value>
        /// The type of the service.
        /// </value>
        public override AuthenticationServiceType ServiceType
        {
            get { return AuthenticationServiceType.External; }
        }

        /// <summary>
        /// Determines if user is directed to another site (i.e. Facebook, Gmail, Twitter, etc) to confirm approval of using
        /// that site's credentials for authentication.
        /// </summary>
        /// <value>
        /// The requires remote authentication.
        /// </value>
        public override bool RequiresRemoteAuthentication
        {
            get { return true; }
        }

        /// <summary>
        /// Gets the login button text.
        /// </summary>
        /// <value>
        /// The login button text.
        /// </value>
        public override string LoginButtonText => "<i class='fa fa-microsoft'></i> AAD B2C";

        /// <summary>
        /// Gets a value indicating whether [supports change password].
        /// </summary>
        /// <value>
        /// <c>true</c> if [supports change password]; otherwise, <c>false</c>.
        /// </value>
        public override bool SupportsChangePassword
        {
            get
            {
                return false;
            }
        }

        /// <summary>
        /// Determines whether two-factor authentication is handled by this authentication component. Populated by an attribute for AADB2C.
        /// </summary>
        /// <returns>
        ///   <c>true</c> if two-factor authentication is handled by this authentication component; otherwise, <c>false</c>.
        /// </returns>
        public override bool IsConfiguredForTwoFactorAuthentication()
        {
            return GetAttributeValue(AttributeKey.SatisfiesMFARequirement).AsBoolean();
        }

        # endregion

        # region Returning From Authentication Detection

        /// <summary>
        /// Tests the Http Request to determine if authentication should be tested by this
        /// authentication provider.
        /// </summary>
        /// <param name="request">The request.</param>
        /// <returns></returns>
        public override Boolean IsReturningFromAuthentication(HttpRequest request)
        {

            return IsReturningFromExternalAuthentication( request.QueryString.ToSimpleQueryStringDictionary() );

        }

        /// <summary>
        /// Examines the request parameters to determine if this request represents a callback from an external auth provider.
        /// </summary>
        /// <param name="parameters">A dictionary of URL parameters.</param>
        /// <returns>True if we are returning from external authentication, false if not.</returns>
        public bool IsReturningFromExternalAuthentication(IDictionary<string, string> parameters)
        {
            return !string.IsNullOrWhiteSpace(parameters.GetValueOrNull("code"));
        }

        # endregion

        # region Login Flow

        /// <summary>
        /// Generates the Login Url.
        /// </summary>
        /// <param name="externalProviderReturnUrl">The callback URL for the external provider (likely the page with the login block).</param>
        /// <param name="successfulAuthenticationRedirectUrl">The URL to which the user should be redirected if the login is successful.</param>
        /// <returns></returns>
        public Uri GenerateExternalLoginUrl(string externalProviderReturnUrl, string successfulAuthenticationRedirectUrl)
        {

            // Check if debug mode enabled
            bool debugModeEnabled = GetAttributeValue("EnableDebugMode").AsBoolean();

            // Set cookies: State, Nonce, Return URL
            var state = EncodeWithBcrypt(System.Guid.NewGuid().ToString());
            var nonce = EncodeWithBcrypt(System.Guid.NewGuid().ToString());

            SetAllCookies(nonce, state, successfulAuthenticationRedirectUrl);

            // Build and return authorization URL
            var cfg = GetOpenIdConnectConfiguration();
            var url = new RequestUrl(cfg.AuthorizationEndpoint);

            var uri = new Uri(url.CreateAuthorizeUrl(
                GetAttributeValue(AttributeKey.ClientId),
                OidcConstants.ResponseTypes.Code,
                OpenIdConnectScope.OpenId,
                externalProviderReturnUrl,
                state,
                nonce
            ));

            if (debugModeEnabled)
            {
                var exceptionText = string.Format("AAB2C Redirect URI: {0}", uri.ToString());
                ExceptionLogService.LogException(new Exception(exceptionText, new Exception(EXCEPTION_DEBUG_TEXT)));
            }

            return uri;

        }

        /// <summary>
        /// Generates the login URL.
        /// </summary>
        /// <param name="request">Forming the URL to obtain user consent</param>
        /// <returns></returns>
        public override Uri GenerateLoginUrl(HttpRequest request)
        {

            var proxySafe = request.UrlProxySafe();

            return GenerateExternalLoginUrl($"{proxySafe.Scheme}://{proxySafe.Host}{proxySafe.AbsolutePath}", request.QueryString[ParameterKey.ReturnUrl]);

        }

        /// <summary>
        /// Authenticate the user upon returning from external authentication.
        /// </summary>
        /// <param name="options">The ExternalRedirectAuthenticationOptions object representing the authentication request.</param>
        /// <returns>The authentication result.</returns>
        public ExternalRedirectAuthenticationResult Authenticate(ExternalRedirectAuthenticationOptions options)
        {

            // Retrieve the current debug mode setting
            bool debugModeEnabled = GetAttributeValue("EnableDebugMode").AsBoolean();

            // Get the default authentication result
            var result = new ExternalRedirectAuthenticationResult
            {
                UserName = string.Empty,
                IsAuthenticated = false
            };

            // Get needed values from URL params
            var code = options.Parameters.GetValueOrNull(ParameterKey.Code);
            var state = options.Parameters.GetValueOrNull(ParameterKey.State);

            // Get all values from the relevant cookies
            string expectedNonce, expectedState, returnUrl;
            GetAllCookies(out expectedNonce, out expectedState, out returnUrl);

            // Validate state
            if ( expectedState.IsNullOrWhiteSpace() || ! state.Equals(expectedState))
            {
                // If the state wasn't valid, throw an exception
                // Relevant cookies will be cleared after the exception is thrown via finally block call.
                throw new Exception("AADB2C: The state value for the returning authentication request was invalid or not set.");
            }

            try
            {

                // Retrieve the OpenIdConnect configuration for AADB2C
                var cfg = GetOpenIdConnectConfiguration();

                // Get the access token
                var client = new TokenClient(cfg.TokenEndpoint, GetAttributeValue(AttributeKey.ClientId), GetAttributeValue(AttributeKey.ClientSecret));
                var response = client.RequestAuthorizationCodeAsync(code, options.RedirectUrl).GetAwaiter().GetResult();

                if (response.IsError)
                {
                    throw new Exception(response.Error);
                }

                // Output access token details if debug mode
                if (debugModeEnabled)
                {
                    var exceptionText = string.Format("AADB2C Access Token: {0}", response.IdentityToken);
                    ExceptionLogService.LogException(new Exception(exceptionText, new Exception(EXCEPTION_DEBUG_TEXT)));
                }

                // Validate access token, null token indicates validation failed
                var claims = ValidateToken( response.IdentityToken, expectedNonce);
                if ( claims == null )
                {
                    throw new Exception("AADB2C: The token failed to validate.");
                }

                // If debug mode is enabled, log exception with claims
                if (debugModeEnabled)
                {
                    var exceptionText = $"AADB2C Token Claims: { claims.ToString() }";
                    ExceptionLogService.LogException(new Exception(exceptionText, new Exception(EXCEPTION_DEBUG_TEXT)));
                }

                // Retrieve user, null or empty username indicates something went wrong
                var username = GetB2CUser(claims);
                if ( username.IsNullOrWhiteSpace() )
                {
                    throw new Exception("AADB2C: Failed to associated Rock user from claims.");
                }

                result.UserName = username;
                result.IsAuthenticated = true;
                result.ReturnUrl = !returnUrl.IsNullOrWhiteSpace() ? returnUrl : string.Empty;

                if ( debugModeEnabled )
                {
                    var exceptionText = string.Format( "UserName: {0}", result.UserName );
                    ExceptionLogService.LogException( new Exception( exceptionText, new Exception( EXCEPTION_DEBUG_TEXT ) ) );
                }

            }

            catch (Exception ex)
            {
                ExceptionLogService.LogException(ex, HttpContext.Current);
            }
            finally
            {
                ExpireAllCookies();
            }

            return result;
        }

        /// <summary>
        /// Authenticates the specified request.
        /// </summary>
        /// <param name="request">The request.</param>
        /// <param name="username">The username.</param>
        /// <param name="returnUrl">The return URL.</param>
        /// <returns></returns>
        public override bool Authenticate(HttpRequest request, out string username, out string returnUrl)
        {

            var proxySafe = request.UrlProxySafe();

            var options = new ExternalRedirectAuthenticationOptions
            {
                RedirectUrl = $"{proxySafe.Scheme}://{proxySafe.Host}{proxySafe.AbsolutePath}",
                Parameters = request.QueryString.ToSimpleQueryStringDictionary()
            };

            var result = Authenticate( options );

            username = result.UserName;
            returnUrl = result.ReturnUrl;

            return result.IsAuthenticated;

        }

        /// <summary>
        /// Gets the name of the B2C user.
        /// </summary>
        /// <param name="b2cUser">The B2C user.</param>
        /// <param name="accessToken">The access token.</param>
        /// <returns></returns>
        public static string GetB2CUser(B2CClaims claims)
        {
            // Claims are required and cannot be null
            if (claims == null)
            {
                return null;
            }

            string email = claims.Email;
            string userId = claims.UserId;

            string userName = $"{AADB2C_SHORT_DESCRIPTOR}_{userId}";
            UserLogin user = null;

            using (var rockContext = new RockContext())
            {

                // Query for an existing user 
                var userLoginService = new UserLoginService(rockContext);
                user = userLoginService.GetByUserName(userName);

                // If no user was found, see if we can find a match in the person table based on given name, family name, and email
                if (user == null)
                {
                    // Get name/email from B2C login
                    string lastName = claims.FamilyName;
                    string firstName = claims.GivenName;

                    Person person = null;

                    // If person had an email, get the first person with the same name and email address.
                    if (email.IsNotNullOrWhiteSpace())
                    {
                        var personService = new PersonService(rockContext);
                        person = personService.FindPerson(firstName, lastName, email, true);
                    }

                    var personRecordTypeId = DefinedValueCache.Get(Rock.SystemGuid.DefinedValue.PERSON_RECORD_TYPE_PERSON.AsGuid()).Id;
                    var personStatusPending = DefinedValueCache.Get(Rock.SystemGuid.DefinedValue.PERSON_RECORD_STATUS_PENDING.AsGuid()).Id;

                    rockContext.WrapTransaction(() =>
                    {
                        if (person == null)
                        {
                            person = new Person();
                            person.IsSystem = false;
                            person.RecordTypeValueId = personRecordTypeId;
                            person.RecordStatusValueId = personStatusPending;
                            person.FirstName = firstName;
                            person.LastName = lastName;
                            person.Email = email;
                            person.IsEmailActive = true;
                            person.EmailPreference = EmailPreference.EmailAllowed;
                            person.Gender = Gender.Unknown;


                            if (person != null)
                            {
                                PersonService.SaveNewPerson(person, rockContext, null, false);
                            }
                        }

                        if (person != null)
                        {
                            int typeId = EntityTypeCache.Get(typeof(AADB2C)).Id;
                            user = UserLoginService.Create(rockContext, person, AuthenticationServiceType.External, typeId, userName, AADB2C_SHORT_DESCRIPTOR, true);
                        }

                    });
                }

                if (user != null)
                {
                    return user.UserName;
                }

                return null;
            }
        }

        # endregion

        # region Helper Methods

        /// <summary>
        /// Get the Open Id Connect configuration available from the specified metadata document.
        /// </summary>
        /// <returns>The Open Id Connect configuration object.</returns>
        private OpenIdConnectConfiguration GetOpenIdConnectConfiguration()
        {

            var metadataUri = GetAttributeValue(AttributeKey.OpenIdConnectMetdataURI);

            var mgr = new ConfigurationManager<OpenIdConnectConfiguration>(metadataUri, new OpenIdConnectConfigurationRetriever());

            return mgr.GetConfigurationAsync().GetAwaiter().GetResult();

        }

        /// <summary>
        /// Encode the provided string with BCrypt.
        /// </summary>
        /// <param name="value">The value to be returned.</param>
        /// <returns>The encoded string.</returns>
        private string EncodeWithBcrypt(string value) => BCrypt.Net.BCrypt.HashPassword(value, BCrypt.Net.BCrypt.GenerateSalt(12));

        /// <summary>
        /// Set values for all cookies to be used by the AADB2C authentication process.
        /// </summary>
        /// <param name="nonce">The nonce value.</param>
        /// <param name="state">The state value.</param>
        /// <param name="returnUrl">The return url.</param>
        private void SetAllCookies(string nonce, string state, string returnUrl)
        {

            SetCookie(CookieKey.Nonce, nonce);
            SetCookie(CookieKey.State, state);
            SetCookie(CookieKey.ReturnUrl, returnUrl);

        }

        /// <summary>
        /// Expire all cookies on the client used as part of the AADB2C authentication flow.
        /// </summary>
        private void ExpireAllCookies()
        {

            ExpireClientCookie(CookieKey.Nonce);
            ExpireClientCookie(CookieKey.State);
            ExpireClientCookie(CookieKey.ReturnUrl);

        }

        /// <summary>
        /// Set a cookie in the current request's HTTP response that will expire in 30 minutes and encrypts the cookie value.
        /// </summary>
        /// <param name="cookieName">The name of the cookie.</param>
        /// <param name="cookieValue">The value to be stored; this will be encrypted using Rock encryption utilities.</param>
        private void SetCookie(string cookieName, string cookieValue)
        {

            // Generate the base cookie
            var cookie = GenerateAADB2CCookie(cookieName);

            // Set the cookie value, encrypted using standard Rock tooling
            cookie.Value = Encryption.EncryptString(cookieValue);

            // Set an expiration, 30 minutes should be plenty of time for auth to complete
            cookie.Expires = DateTime.UtcNow.AddMinutes(30);

            // Set the cookie
            HttpContext.Current.Response.Cookies.Set(cookie);

        }

        /// <summary>
        /// Checks whether or not the current connection is secure (HTTPS).
        /// </summary>
        /// <returns>True if the current connection is secure, false if it is not.</returns>
        private bool IsSecureConnection() => HttpContext.Current.Request.IsSecureConnection || string.Equals(HttpContext.Current.Request.UrlProxySafe().Scheme, "https", StringComparison.OrdinalIgnoreCase);

        /// <summary>
        /// Generates an HttpCookie template using the appropriate flags for AADB2C OIDC authentication.
        /// </summary>
        /// <param name="cookieName">The name of the cookie to be generated.</param>
        /// <returns>The generated cookie object. This isn't yet set in the HTTP response; the caller should do so.</returns>
        private HttpCookie GenerateAADB2CCookie(string cookieName)
        {

            return new HttpCookie(cookieName)
            {
                // Prevent interaction with client-side JS: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie#httponly
                HttpOnly = true,

                // Allow the request from AADB2C back to Rock to send the cookie: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie#samesitesamesite-value
                SameSite = SameSiteMode.Lax,

                // If the transport appears to be secure, set the cookie as secured (must be transmitted over HTTPS) https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie#secure
                Secure = IsSecureConnection(),
            };

        }

        /// <summary>
        /// Get an encrypted cookie value.
        /// </summary>
        /// <param name="cookieName">The name of the cookie to retrieve.</param>
        /// <returns>The cookie value, or an empty string if the cookie was not found.</returns>
        private string GetCookie(string cookieName) =>
         Encryption.DecryptString(HttpContext.Current?.Request?.Cookies[cookieName]?.Value)
         .ToStringSafe() ?? string.Empty;

        /// <summary>
        /// Get values for all of the cookies used by AADB2C in one shot.
        /// </summary>
        /// <param name="nonce">The string to be set to the cookie nonce value that is found.</param>
        /// <param name="state">The string to be set to the cookie state value that is found.</param>
        /// <param name="returnUrl">The string to be set to the cookie returnUrl value that is found.</param>
        private void GetAllCookies(out string nonce, out string state, out string returnUrl)
        {

            nonce = GetCookie( CookieKey.Nonce );
            state = GetCookie ( CookieKey.State );
            returnUrl = GetCookie ( CookieKey.ReturnUrl );

        }

        /// <summary>
        /// Expires a cookie on the client by setting the expiration in the past.
        /// </summary>
        /// <param name="cookieName">The name of the cookie to be expired.</param>
        private void ExpireClientCookie(string cookieName)
        {

            var cookie = GenerateAADB2CCookie(cookieName);
            cookie.Value = string.Empty;
            cookie.Expires = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

            HttpContext.Current.Response.Cookies.Set(cookie);

        }

        /// <summary>
        /// Validate the JWT token returned from the token endpoint.
        /// </summary>
        /// <param name="rawToken">The raw token string.</param>
        /// <param name="nonce">The expected nonce value to be found in the token.</param>
        /// <returns></returns>
        private B2CClaims ValidateToken(string rawToken, string nonce)
        {

            var cfg = GetOpenIdConnectConfiguration();
            TokenValidationParameters validationParams = new TokenValidationParameters
            {
                ValidateAudience = true,
                ValidAudience = GetAttributeValue( AttributeKey.ClientId ),
                ValidateIssuer = true,
                ValidIssuer = cfg.Issuer,
                ValidateLifetime = true,
                IssuerSigningKeys = cfg.SigningKeys,
            };

            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            _ = handler.ValidateToken( rawToken, validationParams, out var token);
            var validToken = token as JwtSecurityToken;

            if ( validToken == null )
            {
                ExceptionLogService.LogException(new Exception("AADB2C: Token signature validation failed."));
                return null;
            }

            if ( nonce.IsNullOrWhiteSpace() || nonce != validToken.GetClaimValue( JwtClaimTypes.Nonce ))
            {
                ExceptionLogService.LogException(new Exception("AADB2C: Token nonce validation failed."));
                return null;
            }

            // Token is valid. Let's create and populate a claims object.
            B2CClaims claims = new B2CClaims
            {
                // The User Id (Guid) for the user in AADB2C
                UserId = validToken.GetClaimValue( JwtClaimTypes.Subject ),

                // The first name / given name from 
                GivenName = validToken.GetClaimValue( JwtClaimTypes.GivenName ),

                // The last name / family name from AADB2C
                FamilyName = validToken.GetClaimValue( JwtClaimTypes.FamilyName ),
                
                //
                Email = validToken.Claims.Where(c => c.Type == ClaimsKey.Emails).FirstOrDefault()?.Value
            };

            var validationResult = claims.HasValidClaims();

            if ( !validationResult )
            {
                ExceptionLogService.LogException(new Exception("AADB2C: A required claim was missing from the token. Required claims are: subject, given name, family name, and email."));
                return null;
            }

            return claims;
        }

        # endregion

        #region Models
        /// <summary>
        /// Model representing the claims returned from AADB2C.
        /// </summary>
        public class B2CClaims
        {

            /// <summary>
            /// The user id for this user object reported by the B2C token.
            /// </summary>
            public string UserId { get; set; }
            
            /// <summary>
            /// The given name (first name) for this user reported by the B2C token.
            /// </summary>
            public string GivenName { get; set; }

            /// <summary>
            /// The family name (last name) for this user reported by the B2C token.
            /// </summary>
            public string FamilyName { get; set; }

            /// <summary>
            /// The email address for this user reported by the B2C token.
            /// </summary>
            public string Email { get; set; }

            /// <summary>
            /// Validates this object's claims (ensure they are all non-empty and non-null).
            /// </summary>
            /// <returns>True if valid, false if not.</returns>
            public bool HasValidClaims()
            {

                if ( UserId.IsNullOrWhiteSpace() || GivenName.IsNullOrWhiteSpace() || FamilyName.IsNullOrWhiteSpace() || Email.IsNullOrWhiteSpace() )
                {
                    return false;
                }

                return true;

            }

            /// <summary>
            /// Writes all claims to a string for debugging purposes.
            /// </summary>
            /// <returns>Writes all claims to a string for debugging purposes.</returns>
            public override string ToString()
            {
                return $"UserId: { UserId }, GivenName: { GivenName }, FamilyName: { FamilyName }, Email: { Email }";
            }

        }
        #endregion

        # region Unimplemented authentication provider methods

        /// <summary>
        /// Gets the URL of an image that should be displayed.
        /// </summary>
        /// <returns></returns>
        /// <exception cref="System.NotImplementedException"></exception>
        public override String ImageUrl()
        {
            return string.Empty;
        }

        /// <summary>
        /// Authenticates the specified user name and password
        /// </summary>
        /// <param name="user">The user.</param>
        /// <param name="password">The password.</param>
        /// <returns></returns>
        public override bool Authenticate(UserLogin user, string password)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Encodes the password.
        /// </summary>
        /// <param name="user">The user.</param>
        /// <param name="password"></param>
        /// <returns></returns>
        public override string EncodePassword(UserLogin user, string password)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Changes the password.
        /// </summary>
        /// <param name="user">The user.</param>
        /// <param name="oldPassword">The old password.</param>
        /// <param name="newPassword">The new password.</param>
        /// <param name="warningMessage">The warning message.</param>
        /// <returns></returns>
        /// <exception cref="System.NotImplementedException"></exception>
        public override bool ChangePassword(UserLogin user, string oldPassword, string newPassword, out string warningMessage)
        {
            warningMessage = "not supported";
            return false;
        }

        /// <summary>
        /// Sets the password.
        /// </summary>
        /// <param name="user">The user.</param>
        /// <param name="password">The password.</param>
        /// <exception cref="System.NotImplementedException"></exception>
        public override void SetPassword(UserLogin user, string password)
        {
            throw new NotImplementedException();
        }

        # endregion
    }
}