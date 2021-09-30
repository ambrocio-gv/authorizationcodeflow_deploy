using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Newtonsoft.Json;
using ResourceApp.Services;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace ResourceApp
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }



        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddHttpClient<IAuthnService, AuthnService>(c => {

                //c.BaseAddress = new Uri("https://authnapi.azurewebsites.net/api/authmanagement/");

                //c.BaseAddress = new Uri("https://localhost:5001/api/authmanagement/");


            });

           services.AddAuthentication(config => {
                // We check the cookie to confirm that we are authenticated
                config.DefaultAuthenticateScheme = "ClientCookie";
                // When we sign in we will deal out a cookie
                config.DefaultSignInScheme = "ClientCookie";
                // use this to check if we are allowed to do something.
                config.DefaultChallengeScheme = "OurServer";
            })
                .AddCookie("ClientCookie")
                .AddOAuth("OurServer", config => {
                    config.ClientId = "client_id";
                    config.ClientSecret = "client_secret";
                    config.CallbackPath = "/oauth/callback";
                    config.UsePkce = true;
                    //config.AuthorizationEndpoint = "https://localhost:44358/oauth/authorize";
                    //config.TokenEndpoint = "https://localhost:44358/oauth/token";

                    //FOR IIS - https redirection is also disabled 
                    config.AuthorizationEndpoint = "https://authenticationserver.local:447/oauth/authorize";
                    config.TokenEndpoint = "https://authenticationserver.local:447/oauth/token";

                    config.SaveTokens = true;

                    config.Events = new OAuthEvents() {
                        OnCreatingTicket = context => {
                            var accessToken = context.AccessToken;
                            var base64payload = accessToken.Split('.')[1];
                            var bytes = Decode.DecodeUrlBase64(base64payload);
                            var jsonPayload = Encoding.UTF8.GetString(bytes);
                            var claims = JsonConvert.DeserializeObject<Dictionary<string, string>>(jsonPayload);

                            foreach (var claim in claims)
                            {
                                context.Identity.AddClaim(new Claim(claim.Key, claim.Value));
                            }

                            return Task.CompletedTask;
                        }
                    };
                
                });

            services.Configure<CookiePolicyOptions>(options =>
            {
                // This lambda determines whether user consent for non-essential cookies is needed for a given request.
                options.CheckConsentNeeded = context => true;
                options.MinimumSameSitePolicy = SameSiteMode.None;
            });

            services.AddHttpClient();

            services.AddDatabaseDeveloperPageExceptionFilter();


            services.AddControllersWithViews()
                .AddRazorRuntimeCompilation();
        }



     
        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }
            app.UseDeveloperExceptionPage();
            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints => {
                endpoints.MapDefaultControllerRoute();
                //endpoints.MapControllerRoute(
                //    name: "default",
                //    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
