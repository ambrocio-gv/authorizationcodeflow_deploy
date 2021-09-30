using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using ResourceApp.Models;
using ResourceApp.Services;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace ResourceApp.Controllers
{
    public class HomeController : Controller
    {
        

        private readonly IAuthnService _authnService;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly HttpClient _client;


        public HomeController(IAuthnService authnService, IHttpClientFactory httpClientFactory)
        {
            _httpClientFactory = httpClientFactory;
            _authnService = authnService;
            _client = httpClientFactory.CreateClient();

        }






        [Authorize]
        public async Task<IActionResult> Secret()
        {
            //var serverResponse = await AccessTokenRefreshWrapper(
            //    () => SecuredGetRequest("https://clientapp.local:444/secret/index")); //this is for development to check the validate route for the access token in server

            var apiResponse = await AccessTokenRefreshWrapper(
            //////    //() => SecuredGetRequest("https://localhost:5001/api/Todo"));
            () => SecuredGetRequest("https://ownedapi.local:446/api/Todo"));



            var token = HttpContext.GetTokenAsync("Token");

            //var token = HttpContext.GetTokenAsync("access_token");

            //_client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");

            ////var serverResponse = await _client.GetAsync("https://localhost:44358/secret/index");

            ////var apiResponse = await _client.GetAsync("https://localhost:5001/secret/index");

            ////txtBlock.Text = await apiResponse.Content.ReadAsStringAsync();

            var responseString = await apiResponse.Content.ReadAsStringAsync();

            //var responseData = JsonConvert.DeserializeObject<Dictionary<string, string>>(responseString);

            List<ItemData> items = JsonConvert.DeserializeObject<List<ItemData>>(responseString);

            //return View();



            return View(items);
        }

        private async Task<HttpResponseMessage> SecuredGetRequest(string url)
        {
            var token = await HttpContext.GetTokenAsync("access_token");
            var client = _httpClientFactory.CreateClient();
            client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");
            return await client.GetAsync(url);
        }

        public async Task<HttpResponseMessage> AccessTokenRefreshWrapper(
            Func<Task<HttpResponseMessage>> initialRequest)
        {
            var response = await initialRequest();

            if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
            {
                await RefreshAccessToken();
                response = await initialRequest();
            }

            return response;
        }

        private async Task RefreshAccessToken()
        {
            var refreshToken = await HttpContext.GetTokenAsync("refresh_token");

            var refreshTokenClient = _httpClientFactory.CreateClient();

            var requestData = new Dictionary<string, string> {
                ["grant_type"] = "refresh_token",
                ["refresh_token"] = refreshToken
            };

            var request = new HttpRequestMessage(HttpMethod.Post, "https://authenticationserver.local:447/oauth/token") {
                Content = new FormUrlEncodedContent(requestData) // required Content-Type: application/x-www-form-urlencoded
            };

            var basicCredentials = "usernameandpassword"; //this should be the client secret?
            var encodedCredentials = Encoding.UTF8.GetBytes(basicCredentials);


            var base64Credentials = Convert.ToBase64String(encodedCredentials);
            
            request.Headers.Add("Authorization", $"Basic {base64Credentials}");

            var response = await refreshTokenClient.SendAsync(request); //request is http request message 

            var responseString = await response.Content.ReadAsStringAsync();
            var responseData = JsonConvert.DeserializeObject<Dictionary<string, string>>(responseString);

            var newAccessToken = responseData.GetValueOrDefault("access_token");
            var newRefreshToken = responseData.GetValueOrDefault("refresh_token");

            var authInfo = await HttpContext.AuthenticateAsync("ClientCookie");// will bring up the authentication information of the current section

            authInfo.Properties.UpdateTokenValue("access_token", newAccessToken);
            authInfo.Properties.UpdateTokenValue("refresh_token", newRefreshToken);

            await HttpContext.SignInAsync("ClientCookie", authInfo.Principal, authInfo.Properties);// all of the initial claims are retained 
        }

        //login
        public async Task<IActionResult> Index()
        {
            //try
            //{
            //    //var token = await _authnService.GetToken();
            //}
            //catch(Exception ex)
            //{
            //    Debug.Write(ex);
            //}

            return View();
        }

        //register
        [Authorize]
        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
