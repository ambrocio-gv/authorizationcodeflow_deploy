using TAuthServer.Configuration;
using TAuthServer.Data;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TAuthServer;

namespace TAuthServer
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

            services.Configure<JwtConfig>(Configuration.GetSection("JwtConfig"));

            services.AddDbContext<ApiDbContext>(options =>
                options.UseSqlServer(
                    Configuration.GetConnectionString("DefaultConnection")));

            //ConfigureApplicationCookie does not work with AddDefaultIdentity


            services.AddIdentity<IdentityUser, IdentityRole>(options => options.SignIn.RequireConfirmedAccount = true)
                .AddEntityFrameworkStores<ApiDbContext>(); // changed services.AddDefaultIdentity<IdentityUser>(); //Redirects to Account/Login
                                                           //services.AddIdentity<IdentityUser, IdentityRole>(); //Redirects to Account/LoginRegister 

            services.ConfigureApplicationCookie(options => {
                options.LoginPath = $"/";
            }); //changed login path to null because default is Account/LoginRegister 


            var key = Encoding.ASCII.GetBytes(Configuration["JwtConfig:Secret"]);

            var tokenValidationParams = new TokenValidationParameters
            {
                //ValidateIssuerSigningKey = true,
                //IssuerSigningKey = new SymmetricSecurityKey(key),
                //ValidateIssuer = false,
                //ValidateAudience = false,
                //ValidateLifetime = true,
                //RequireExpirationTime = false
                ClockSkew = TimeSpan.Zero, // the access token doesn't expire because of clock skew so it is now set as zero
                ValidIssuer = Constants.Issuer,
                ValidAudience = Constants.Audiance,
                IssuerSigningKey = new SymmetricSecurityKey(key)
            };

            services.AddSingleton(tokenValidationParams);

            //services.AddAuthentication(options => {
            //    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            //    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
            //    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;


            //})
            //.AddJwtBearer(config => {

            //    config.SaveToken = true;
            //    config.TokenValidationParameters = tokenValidationParams;
            //    config.Events = new JwtBearerEvents() {
            //        OnMessageReceived = context => {
            //            if (context.Request.Query.ContainsKey("access_token"))
            //            {
            //                context.Token = context.Request.Query["access_token"];
            //            }

            //            return Task.CompletedTask;
            //        }
            //    };
            //});

            services.AddAuthentication("OAuth")
                .AddJwtBearer("OAuth", config => {
                    //var secretBytes = Encoding.UTF8.GetBytes(Constants.Secret);
                    //var key = new SymmetricSecurityKey(secretBytes);

                    config.Events = new JwtBearerEvents()
                    {
                        OnMessageReceived = context => {
                            if (context.Request.Query.ContainsKey("access_token"))
                            {
                                context.Token = context.Request.Query["access_token"];
                            }

                            return Task.CompletedTask;
                        }
                    };

                    config.TokenValidationParameters = tokenValidationParams;
                });






            





            services.AddControllersWithViews()
                .AddRazorRuntimeCompilation();



            services.AddControllers();
            //services.AddSwaggerGen(c => {
            //    c.SwaggerDoc("v1", new OpenApiInfo { Title = "AuthnAPI", Version = "v1" });
            //});
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                //app.UseSwagger();
                //app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "AuthnAPI v1"));
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

            app.UseEndpoints(endpoints =>
            {
                //endpoints.MapControllerRoute(
                //       name: "default",
                //       pattern: "{controller=Home}/{action=Index}/{id?}");
                //endpoints.MapControllers();
                endpoints.MapDefaultControllerRoute();
            });
        }
    }
}
