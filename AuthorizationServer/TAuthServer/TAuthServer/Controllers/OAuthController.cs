using TAuthServer.Configuration;
using TAuthServer.Data;
using TAuthServer.Models.DTO.Requests;
using TAuthServer.Models.DTO.Responses;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;


namespace TAuthServer.Controllers
{
 
        public class OAuthController : Controller
        {
            private readonly UserManager<IdentityUser> _userManager;

            private readonly JwtConfig _jwtConfig;

            private readonly TokenValidationParameters _tokenValidationParams;

            private readonly ApiDbContext _apiDbContext;

            private static IdentityUser currentUser;

            private static string codeChallenge;

            private static string authorizationCode;

            private static string storeRedirectUri;

            private static string storeAuthState;

            public OAuthController(
                UserManager<IdentityUser> userManager,
                IOptionsMonitor<JwtConfig> optionsMonitor,
                TokenValidationParameters tokenValidationParams,
                ApiDbContext apiDbContext)
            {
                _userManager = userManager;
                _jwtConfig = optionsMonitor.CurrentValue;
                _tokenValidationParams = tokenValidationParams;
                _apiDbContext = apiDbContext;
            }


            private static string GenerateNonce()
            {
                const string chars = "abcdefghijklmnopqrstuvwxyz123456789";
                var random = new Random();
                var nonce = new char[128];
                for (int i = 0; i < nonce.Length; i++)
                {
                    nonce[i] = chars[random.Next(chars.Length)];
                }

                return new string(nonce);
            }


            private static string GenerateCodeChallenge(string codeVerifier)
            {
                using var sha256 = SHA256.Create();
                var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
                var b64Hash = Convert.ToBase64String(hash);
                var code = Regex.Replace(b64Hash, "\\+", "-");
                code = Regex.Replace(code, "\\/", "_");
                code = Regex.Replace(code, "=+$", "");
                return code;
            }

            [HttpGet]
            public IActionResult Register(
               string code_challenge_method,
               string code_challenge,
               string response_type, // authorization flow type 
               string client_id, // client id
               string redirect_uri,
               string scope, // what info I want = email,grandma,tel
               string state) // random string generated to confirm that we are going to back to the same client
            {

                var model = new UserRegistrationDto();

                //var query = new QueryBuilder();
                //query.Add("redirectUri", redirect_uri);
                //query.Add("state", state);
                //query.Add("code_challenge_method", code_challenge_method);
                //query.Add("code_challenge", code_challenge);
                return View(model); //returns the login view
            }

            [HttpPost]
            public async Task<IActionResult> Register(
               string username,
               string password,
               string response_type, // authorization flow type 
               string client_id, // client id
               string redirect_uri,
               string scope) // random string generated to confirm that we are going to back to the same client
            {

                var user = new UserRegistrationDto();

                user.Email = username;
                user.Password = password;

                if (ModelState.IsValid)
                {
                    // We can utilize model
                    var existingUser = await _userManager.FindByEmailAsync(user.Email); //there can only be one user with that email in the system

                    if (existingUser != null)
                    {
                        return BadRequest(new RegistrationResponse()
                        {
                            Errors = new List<string>()
                        {
                            "Email already in use"
                        },
                            Success = false
                        });
                    }

                    var newUser = new IdentityUser() { Email = user.Email, UserName = user.Email };
                    var isCreated = await _userManager.CreateAsync(newUser, user.Password);
                    if (isCreated.Succeeded)
                    {
                        return RedirectToAction(actionName: "Authorize");
                    }
                    else
                    {
                        return BadRequest(new RegistrationResponse()
                        {
                            Errors = isCreated.Errors.Select(x => x.Description).ToList(),
                            Success = false
                        });
                    }

                }

                return BadRequest(new RegistrationResponse()
                {
                    Errors = new List<string>()
                {
                    "Invalid values"
                },
                    Success = false
                });

            }









            [HttpGet]
            public IActionResult Authorize(
                string code_challenge_method,
                string code_challenge,
                string response_type, // authorization flow type 
                string client_id, // client id
                string redirect_uri,
                string scope, // what info I want = email,grandma,tel
                string state) // random string generated to confirm that we are going to back to the same client
            {

                if (code_challenge != null)
                {
                    codeChallenge = code_challenge;
                }
                if (redirect_uri != null)
                {
                    storeRedirectUri = redirect_uri;
                }
                if (state != null)
                {
                    storeAuthState = state;
                }


                var query = new QueryBuilder();
                query.Add("redirectUri", storeRedirectUri);
                query.Add("state", storeAuthState);

                return View(model: query.ToString()); //returns the login view
            }





            //LOGIN - server sends authorization code once login is good //change name to login later //can be in api controller no views returned only redirect
            [HttpPost]
            public async Task<IActionResult> Authorize(
                string username,
                string password,
                string redirectUri, //personal note: not sure why the name has to change 
                string state)
            {

                var user = new UserLoginRequest();

                user.Email = username;
                user.Password = password;

                if (ModelState.IsValid)
                {
                    var existingUser = await _userManager.FindByEmailAsync(user.Email);//email-username

                    if (existingUser == null)
                    {
                        return BadRequest(new RegistrationResponse()
                        {
                            Errors = new List<string>() {
                                "Invalid login request"
                            },
                            Success = false
                        });
                    }

                    var isCorrect = await _userManager.CheckPasswordAsync(existingUser, user.Password);

                    currentUser = existingUser;

                    if (!isCorrect)
                    {
                        return BadRequest(new RegistrationResponse()
                        {
                            Errors = new List<string>() {
                                "Invalid login request"
                            },
                            Success = false
                        });
                    }

                    //send authorization code if login is good 
                    var code = GenerateNonce();

                    authorizationCode = code;

                    var query = new QueryBuilder();
                    query.Add("code", code);
                    query.Add("state", state);

                    //query.Add("existinguser", (IEnumerable<string>)existingUser);

                    return Redirect($"{redirectUri}{query.ToString()}"); // pass  var jwtToken = await GenerateJwtToken(existingUser);
                }

                return BadRequest(new RegistrationResponse()
                {
                    Errors = new List<string>() {
                            "Invalid login request"
                        },
                    Success = false
                });

            }

            //Authorization code is sent back + client ID + client secret to /oauth/token
            public async Task<IActionResult> Token(
                string code_verifier,
                string grant_type, // flow of access_token request
                string code, // confirmation of the authentication process
                string redirect_uri,
                string client_id,
                string client_secret,
                string refresh_token,
                string existinguser)
            {
                var convertedToCodeChallenge = GenerateCodeChallenge(code_verifier);

                if (code != authorizationCode && convertedToCodeChallenge != codeChallenge)
                {
                    return BadRequest(new AuthResult()
                    {
                        Errors = new List<string>() {
                            "Invalid Authorization Code / Code Verifier"
                        },
                        Success = false
                    });
                }




                //mising logic to validate the authorization code - DO WITH PKECE
                //if(code != "RANDOMAUTHORIZATIONCODE" && client_id != "client_id" && client_secret != "client_secret")
                //{
                //    return BadRequest(new AuthResult() {
                //        Errors = new List<string>() {
                //                "Invalid Authorization Code / Client Id / Client Secret"
                //            },
                //        Success = false
                //    });
                //}

                var user = currentUser;

                var claims = new[] {
                new Claim ("Id", user.Id),
                new Claim (JwtRegisteredClaimNames.Email, user.Email),
                new Claim (JwtRegisteredClaimNames.Sub, user.Email),
                new Claim (JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };



                var secretBytes = Encoding.UTF8.GetBytes(_jwtConfig.Secret);
                var key = new SymmetricSecurityKey(secretBytes);

                var algorithm = SecurityAlgorithms.HmacSha256;
                var signingCredentials = new SigningCredentials(key, algorithm);


                var token = new JwtSecurityToken(
                    Constants.Issuer,
                    Constants.Audiance,
                    claims,
                    notBefore: DateTime.Now,
                    expires: grant_type == "refresh_token" //required - must make a request through the token endpoint 
                        ? DateTime.Now.AddMinutes(5)
                        : DateTime.Now.AddMilliseconds(1), // if its not a refresh token but an access token it will expire right away 1ms
                    signingCredentials);

                var access_token = new JwtSecurityTokenHandler().WriteToken(token);





                var responseObject = new
                {
                    access_token,
                    token_type = "Bearer",
                    raw_claim = "oauthTutorial",
                    refresh_token = "RefreshTokenSampleValueSomething77" //temporary can be any string 

                };

                var responseJson = JsonConvert.SerializeObject(responseObject);
                var responseBytes = Encoding.UTF8.GetBytes(responseJson);

                await Response.Body.WriteAsync(responseBytes, 0, responseBytes.Length);


                return Redirect(redirect_uri);

            }

            [Authorize]
            public IActionResult Validate()
            {
                if (HttpContext.Request.Query.TryGetValue("access_token", out var accessToken)) //to implement AuthManagementController VerifyandGenerateToken Method
                {

                    ////validation 1 - check if it is a jwttoken format in our program via tokenValidationParams
                    //var tokenInVerification = jwtTokenHandler.ValidateToken(tokenRequest.Token, _tokenValidationParams, out var validatedToken);

                    ////validation 2 - check using the security algorithm selected , it's encryption
                    //if (validatedToken is JwtSecurityToken jwtSecurityToken)
                    //{
                    //    var result = jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCulture);

                    //    if (result == false)
                    //    {
                    //        return null;
                    //    }
                    //}

                    ////validation 3 - check if the token is not yet expired
                    //var utcExpiryDate = long.Parse(tokenInVerification.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Exp).Value);

                    //var expiryDate = UnixTimeStampToDateTime(utcExpiryDate);

                    //if (expiryDate > DateTime.UtcNow)
                    //{
                    //    return new AuthResult() {
                    //        Success = false,
                    //        Errors = new List<string>() {
                    //            "Token has not yet expired"
                    //        }
                    //    };
                    //}

                    ////validation 4 - check against api dbcontext if it exists within the database of the token
                    //var storedToken = await _apiDbContext.RefreshTokens.FirstOrDefaultAsync(x => x.Token == tokenRequest.RefreshToken);

                    //if (storedToken == null)
                    //{
                    //    return new AuthResult() {
                    //        Success = false,
                    //        Errors = new List<string>() {
                    //            "Token does not exist"
                    //        }
                    //    };
                    //}

                    ////validation 5 - check to see if the token has already been used 
                    //if (storedToken.IsUsed)
                    //{
                    //    return new AuthResult() {
                    //        Success = false,
                    //        Errors = new List<string>() {
                    //            "Token has been used"
                    //        }
                    //    };
                    //}

                    ////validation 6 - check if the token has been revoked or not
                    //if (storedToken.IsRevoked)
                    //{
                    //    return new AuthResult() {
                    //        Success = false,
                    //        Errors = new List<string>() {
                    //            "Token has been revoked"
                    //        }
                    //    };
                    //}

                    ////validation 7 - check jti matches the id of the refresh token
                    //var jti = tokenInVerification.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Jti).Value;

                    //if (storedToken.JwtId != jti)
                    //{
                    //    return new AuthResult() {
                    //        Success = false,
                    //        Errors = new List<string>() {
                    //            "Token doesn't match"
                    //        }
                    //    };
                    //}




                    return Ok();
                }

                return BadRequest();
            }







        }
    
}