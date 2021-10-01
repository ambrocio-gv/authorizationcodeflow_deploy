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
            }


            private static string GenerateRandom()
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
               string response_type, 
               string client_id, 
               string redirect_uri,
               string scope,
               string state) 
            {
                var model = new UserRegistrationDto();
                return View(model); 
            }

            [HttpPost]
            public async Task<IActionResult> Register(
               string username,
               string password,
               string response_type, 
               string client_id, 
               string redirect_uri,
               string scope)
            {

                var user = new UserRegistrationDto();

                user.Email = username;
                user.Password = password;

                if (ModelState.IsValid)
                {
                    var existingUser = await _userManager.FindByEmailAsync(user.Email); 

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
                string response_type,
                string client_id, 
                string redirect_uri,
                string scope, 
                string state) 
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

                return View(model: query.ToString()); 
            }

            [HttpPost]
            public async Task<IActionResult> Authorize(
                string username,
                string password,
                string redirectUri, 
                string state)
            {

                var user = new UserLoginRequest();

                user.Email = username;
                user.Password = password;

                if (ModelState.IsValid)
                {
                    var existingUser = await _userManager.FindByEmailAsync(user.Email);

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

                    var code = GenerateRandom();

                    authorizationCode = code;

                    var query = new QueryBuilder();
                    query.Add("code", code);
                    query.Add("state", state);

                    return Redirect($"{redirectUri}{query.ToString()}"); 
                }

                return BadRequest(new RegistrationResponse()
                {
                    Errors = new List<string>() {
                            "Invalid login request"
                        },
                    Success = false
                });

            }

            public async Task<IActionResult> Token(
                string code_verifier,
                string grant_type, 
                string code,
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
                    expires: grant_type == "refresh_token" 
                        ? DateTime.Now.AddMinutes(5)
                        : DateTime.Now.AddMilliseconds(1), 
                    signingCredentials);

                var access_token = new JwtSecurityTokenHandler().WriteToken(token);

                var responseObject = new
                {
                    access_token,
                    token_type = "Bearer",
                    raw_claim = "oauthTutorial",
                    refresh_token = "RefreshTokenSampleValueSomething77" 
                };

                var responseJson = JsonConvert.SerializeObject(responseObject);
                var responseBytes = Encoding.UTF8.GetBytes(responseJson);

                await Response.Body.WriteAsync(responseBytes, 0, responseBytes.Length);

                return Redirect(redirect_uri);

            }

            [Authorize]
            public IActionResult Validate()
            {
                if (HttpContext.Request.Query.TryGetValue("access_token", out var accessToken)) 
                {
                    return Ok();
                }

                return BadRequest();
            }







        }
    
}