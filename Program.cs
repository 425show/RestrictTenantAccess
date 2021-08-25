using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.Identity.Web;
using Microsoft.Identity.Web.UI;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

//ensure you're using Auth Code with PKCE
//builder.Services.Configure<MicrosoftIdentityOptions>(x => x.ResponseType = "code");
/*{
    //x.ResponseType = "code";
    var allowedTenantIds = builder.Configuration["AllowedTenantIds"].Split(",");
    x.TokenValidationParameters.ValidIssuers = allowedTenantIds;
});
*/
builder.Services.Configure<OpenIdConnectOptions>(options =>
{
    options.Events = new OpenIdConnectEvents
    {
        OnTokenResponseReceived = async context =>
        {
            var allowedTenantIds = builder.Configuration["AllowedTenantIds"].Split(",");
            var rawIdToken = context.TokenEndpointResponse.IdToken;
            var handler = new JwtSecurityTokenHandler();
            var idToken = handler.ReadJwtToken(rawIdToken);
            var issuer = idToken.Claims.First(x => x.Type.Equals("iss")).Value;
            var issuerId = issuer.Split("/").Last();
            if (!allowedTenantIds.Contains(issuerId))
            {
                throw new UnauthorizedAccessException("The current Azure AD tenant is not supported by this application");
            }

            await Task.FromResult(0);
        }
    };
});

// Add services to the container.
builder.Services.AddMicrosoftIdentityWebAppAuthentication(builder.Configuration);

builder.Services.AddAuthorization(options =>
{
    // By default, all incoming requests will be authorized according to the default policy.
    options.FallbackPolicy = options.DefaultPolicy;
});

builder.Services.AddRazorPages()
    .AddMicrosoftIdentityUI();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapRazorPages();
app.MapControllers();

app.Run();
