using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;

namespace TodoAPI.AuthRequirements
{
    public class JwtRequirement : IAuthorizationRequirement { }

    public class JwtRequirementHandler : AuthorizationHandler<JwtRequirement>
    {
        private readonly HttpClient _client;
        private readonly HttpContext _httpContext;

        public JwtRequirementHandler(
            IHttpClientFactory httpClientFactory,
            IHttpContextAccessor httpContextAccessor)
        {
            _client = httpClientFactory.CreateClient(); // whats going to send the token to the server
            _httpContext = httpContextAccessor.HttpContext; // this is where we are getting the token 
        }

        protected override async Task HandleRequirementAsync(
            AuthorizationHandlerContext context,
            JwtRequirement requirement)
        {
            if (_httpContext.Request.Headers.TryGetValue("Authorization", out var authHeader))
            {
                var accessToken = authHeader.ToString().Split(' ')[1];

                var response = await _client
                    .GetAsync($"https://authenticationserver.local:447/oauth/validate?access_token={accessToken}");

                if (response.StatusCode == System.Net.HttpStatusCode.OK)
                {
                    context.Succeed(requirement);
                }
            }
        }
    }





}
