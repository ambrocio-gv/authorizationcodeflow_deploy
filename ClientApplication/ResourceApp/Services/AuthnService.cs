using AuthnAPI.Configuration;
using Newtonsoft.Json;
using ResourceApp.Configuration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace ResourceApp.Services
{
    public class AuthnService : IAuthnService
    {
        private readonly HttpClient _httpClient;

        public AuthnService(HttpClient httpClient)
        {
            _httpClient = httpClient;
        }

        public async Task<string> GetToken()
        {
            var request = new HttpRequestMessage(HttpMethod.Post,  "login");

            //IEnumerable<KeyValuePair<string, string>> logindata = new List<KeyValuePair<string, string>>() {
            //    new KeyValuePair<string, string>("email","e@e.com"),
            //    new KeyValuePair<string, string>("password", "password10A!")
            //};

            var payload = new Credential {
                //username = "g@g.com",
                email = "g@g.com",
                password = "password10A!"
            };

            var stringPayload = JsonConvert.SerializeObject(payload);

            var httpContent = new StringContent(stringPayload, Encoding.UTF8, "application/json");

            request.Content = httpContent;

            //request.Content = new FormUrlEncodedContent(logindata);

            var response = await _httpClient.SendAsync(request);

            response.EnsureSuccessStatusCode();

            var responseStream = await response.Content.ReadAsStringAsync();
            var authresult = JsonConvert.DeserializeObject<AuthResult>(responseStream);

            return authresult.Token;



        }

    }
}
