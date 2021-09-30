
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using TodoAPI.Models;
using Microsoft.EntityFrameworkCore;
using TodoAPI.Configuration;
using TodoAPI.Data;
using TodoAPI.Models.DTO.Responses;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication.JwtBearer;


namespace TodoAPI.Controllers
{
    [Route("api/[controller]")] // api/authManagement
    [ApiController]
    public class AuthManagementController : ControllerBase
    {
        //private readonly UserManager<IdentityUser> _userManager;

        private readonly JwtConfig _jwtConfig;

        private readonly TokenValidationParameters _tokenValidationParams;

        private readonly ApiDbContext _apiDbContext;

        public AuthManagementController(
            //UserManager<IdentityUser> userManager,
            IOptionsMonitor<JwtConfig> optionsMonitor,
            TokenValidationParameters tokenValidationParams,
            ApiDbContext apiDbContext)
        {
            //_userManager = userManager;
            _jwtConfig = optionsMonitor.CurrentValue;
            _tokenValidationParams = tokenValidationParams;
            _apiDbContext = apiDbContext;
        }

   
        [HttpPost]
        [Route("token")]
        public async Task<IActionResult> Token([FromBody] TokenRequest tokenRequest)
        {
            if (ModelState.IsValid)
            {
                var result = await VerifyToken(tokenRequest);

                if (result == null)
                {
                    return BadRequest(new RegistrationResponse() {
                        Errors = new List<string>() {
                            "Invalid token - may be expired"
                        },
                        Success = false
                    });
                }
               

                return Ok(result);

            }
            return BadRequest(new RegistrationResponse() {
                Errors = new List<string>() {
                    "Invalid Payload"
                },
                Success = false
            });
        }


        private async Task<AuthResult> VerifyToken(TokenRequest tokenRequest)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();
     
            try
            {   
                //validation 1 - check if it is a jwttoken format in our program via tokenValidationParams
                var tokenInVerification = jwtTokenHandler.ValidateToken(tokenRequest.Token, _tokenValidationParams, out var validatedToken);

                //validation 2 - check using the security algorithm selected , it's encryption
                if(validatedToken is JwtSecurityToken jwtSecurityToken)
                {
                    var result = jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCulture);

                    if(result == false)
                    {
                        return null;
                    }
                }

                //validation 3 - check if the token is not yet expired
                var utcExpiryDate = long.Parse(tokenInVerification.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Exp).Value);

                var expiryDate = UnixTimeStampToDateTime(utcExpiryDate);

                if (expiryDate > DateTime.UtcNow)
                {
                    return new AuthResult() {
                        Success = false,
                        Errors = new List<string>() {
                            "Token has not yet expired"
                        }
                    };
                }            


                return new AuthResult() {                    
                    Success = true
                };

            }
            catch (Exception ex)
            {
                return null;
            }

        }

        private DateTime UnixTimeStampToDateTime(long unixTimeStamp)
        {
            var dateTimeVal = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            dateTimeVal = dateTimeVal.AddSeconds(unixTimeStamp).ToUniversalTime();
            return dateTimeVal;
        }
      


        [HttpPost]
        [Route("jwtdecode")]
        public async Task<IActionResult> DecodeJwt([FromBody] string jwtstring)
        {

            var bytes = Convert.FromBase64String(jwtstring);
            return Ok(Encoding.UTF8.GetString(bytes));
     
        }

        //[HttpGet]
        //[Route("Token")]
        //private async Task<IActionResult> ConvertToken(TokenRequest tokenRequest)
        //{
        //    var token = Temp.SampleToken;
        //    var handler = new JwtSecurityTokenHandler();
        //    var jsonToken = handler.ReadJwtToken(token);

        //    return Ok(jsonToken);
        //}

        //must put token in header
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        [HttpPost]
        [Route("claim")]
        public ActionResult<string> StoreClaims()
        {
            //var idClaim = User.Claims.FirstOrDefault(x => x.Type.Equals("id", StringComparison.InvariantCultureIgnoreCase));
            //if (idClaim != null)
            //{
            //    return Ok($"This is your Id: {idClaim.Subject}");
            //}
            //return BadRequest("No claim");

   
            var identity = HttpContext.User.Identity as ClaimsIdentity;

            IEnumerable<Claim> claimsEnumerable = identity.Claims;

            var claims = claimsEnumerable.ToList();

            var jwtclaim = new JwtClaim();
            jwtclaim.UserId = claims.GetClaim("Id");
            jwtclaim.Email = claims.GetClaim(ClaimTypes.Email);
            jwtclaim.Subject = claims.GetClaim(ClaimTypes.NameIdentifier);
            jwtclaim.JwtId = claims.GetClaim(JwtRegisteredClaimNames.Jti);
            jwtclaim.NotBefore = claims.GetClaim(JwtRegisteredClaimNames.Nbf);
            jwtclaim.Expiry = claims.GetClaim(JwtRegisteredClaimNames.Exp);
            jwtclaim.IssuedAt = claims.GetClaim(JwtRegisteredClaimNames.Iat);

            if (ModelState.IsValid)
            {
                _apiDbContext.JwtClaims.Add(jwtclaim);
                _apiDbContext.SaveChanges();

                return CreatedAtAction("StoreClaims", new { jwtclaim.Id }, jwtclaim);
            }

            return new JsonResult("Something went wrong") { StatusCode = 500 };

        }
        

    }
    public static class Extenstions
    {
        public static string GetClaim(this List<Claim> claims, string name)
        {
            return claims.FirstOrDefault(c => c.Type == name)?.Value;
        }
    }
}
