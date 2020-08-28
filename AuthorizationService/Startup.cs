using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using AuthorizationService.Models;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Security.Cryptography;

namespace AuthorizationService
{
    public class Startup
    {
        public readonly IConfiguration appConfig;
        
        public Startup(IConfiguration configuration)
        {
            appConfig = configuration;
        }

        public void ConfigureServices(IServiceCollection services)
        {
            var tokenSection = appConfig.GetSection("TokenSettings");
            var tokenSettings = tokenSection.Get<TokenSettings>();
            services.Configure<TokenSettings>(tokenSection);

            services.AddControllers()
                .ConfigureApiBehaviorOptions(options => {
                    options.SuppressMapClientErrors = true;
                    options.SuppressModelStateInvalidFilter = true;
                });

            services.AddHttpClient();
            services.Configure<KestrelServerOptions>(options =>
            {
                options.AllowSynchronousIO = true;
            });

            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
                {
                    options.RequireHttpsMetadata = false;
                    options.TokenValidationParameters = new TokenValidationParameters()
                    {
                        ValidateIssuer = true,
                        ValidIssuer = tokenSettings.Issuer,
                        ValidateAudience = true,
                        ValidAudience = tokenSettings.Audience,
                        ValidateLifetime = true,
                        IssuerSigningKey = tokenSettings.GetSecurityKey(),
                        ValidateIssuerSigningKey = true,
                        TokenDecryptionKey = tokenSettings.GetSecurityKey()
                    };

                    options.Events = new JwtBearerEvents()
                    {
                        OnTokenValidated = context =>
                        {
                            if (!context.Request.Cookies.ContainsKey("Fgp"))
                            {
                                context.Fail($"Reason");
                                return Task.CompletedTask;
                            }

                            string cookieFgp = context.Request.Cookies["Fgp"];
                            Claim jwtFgp = context.Principal.Claims.FirstOrDefault(c => c.Type == "fgp");
                            if(jwtFgp == null)
                            {
                                context.Fail($"Reason");
                                return Task.CompletedTask;
                            }

                            if(ComputeSha256Hash(cookieFgp) != jwtFgp.Value)
                            {
                                context.Fail($"Reason");
                                return Task.CompletedTask;
                            }
                            return Task.CompletedTask;
                        }
                    };
                });

            services.AddControllersWithViews();
        }

        private string ComputeSha256Hash(string rawData)
        {
            using (SHA256 sha256Hash = SHA256.Create())
            {
                byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(rawData));
                StringBuilder builder = new StringBuilder();
                for (int i = 0; i < bytes.Length; i++)
                    builder.Append(bytes[i].ToString("x2"));

                return builder.ToString();
            }
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });

            app.UseStaticFiles();
        }
    }
}
