using AuthMicroservice.DTOs;
using AuthMicroservice.Models;
using AuthMicroservice.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Google;
using System.Security.Claims;
using System.Text.Json;
using UserInfo = AuthMicroservice.DTOs.UserInfo;
using AuthMicroservice.Middleware.Data;

namespace AuthMicroservice.Extensions;

public static class EndpointConfiguration
{
    public static void ConfigureEndpoints(this WebApplication app)
    {
        // Basic test endpoints
        app.ConfigureTestEndpoints();
        
        // Auth endpoints
        app.ConfigureAuthEndpoints();
    }

    private static void ConfigureTestEndpoints(this WebApplication app)
    {
        app.MapGet("/", () => "Auth Microservice is running with enhanced security features!")
            .WithName("Home")
            .WithOpenApi()
            .WithSummary("Service status endpoint");

        app.MapGet("/health", () => new { Status = "Healthy", Timestamp = DateTime.UtcNow, Features = new[] { "JWT", "OAuth2", "Email", "Rate Limiting" } })
            .WithName("HealthCheck")
            .WithOpenApi()
            .WithSummary("Health check endpoint");

        app.MapGet("/test-config", (IConfiguration config) =>
        {
            var connectionString = config.GetConnectionString("DefaultConnection");
            var jwtConfigured = !string.IsNullOrEmpty(config["JwtSettings:Secret"]);
            var googleConfigured = !string.IsNullOrEmpty(config["Authentication:Google:ClientId"]);
            
            return Results.Ok(new { 
                ConnectionString = connectionString,
                HasConnectionString = !string.IsNullOrEmpty(connectionString),
                DatabaseProvider = "SQLite",
                JwtConfigured = jwtConfigured,
                GoogleOAuthConfigured = googleConfigured,
                Timestamp = DateTime.UtcNow
            });
        })
        .WithName("TestConfig")
        .WithOpenApi()
        .WithSummary("Configuration test endpoint");

        app.MapGet("/test-db", async (AuthDbContext context) =>
        {
            try
            {
                var userCount = await context.Users.CountAsync();
                var roleCount = await context.Roles.CountAsync();
                return Results.Ok(new { 
                    Message = "Database connected successfully!", 
                    UserCount = userCount,
                    RoleCount = roleCount,
                    DatabaseProvider = "SQLite",
                    Timestamp = DateTime.UtcNow
                });
            }
            catch (Exception ex)
            {
                return Results.BadRequest(new { 
                    Error = "Database connection failed", 
                    Details = ex.Message,
                    DatabaseProvider = "SQLite"
                });
            }
        })
        .WithName("TestDatabase")
        .WithOpenApi()
        .WithSummary("Database connectivity test");

        // Enhanced health check endpoint
        app.MapHealthChecks("/health/detailed", new Microsoft.AspNetCore.Diagnostics.HealthChecks.HealthCheckOptions
        {
            ResponseWriter = async (context, report) =>
            {
                context.Response.ContentType = "application/json";
                var response = new
                {
                    Status = report.Status.ToString(),
                    TotalDuration = report.TotalDuration.TotalMilliseconds,
                    Entries = report.Entries.Select(e => new
                    {
                        Name = e.Key,
                        Status = e.Value.Status.ToString(),
                        Duration = e.Value.Duration.TotalMilliseconds,
                        Description = e.Value.Description
                    })
                };
                await context.Response.WriteAsync(JsonSerializer.Serialize(response));
            }
        }).WithName("DetailedHealthCheck").WithOpenApi();
    }

    private static void ConfigureAuthEndpoints(this WebApplication app)
    {
        var authGroup = app.MapGroup("/api/auth").WithTags("Authentication");

        // Register endpoint
        authGroup.MapPost("/register", async (RegisterRequest request, UserManager<ApplicationUser> userManager, ITokenService tokenService, IEmailService emailService, IValidationService validationService) =>
        {
            // Validate input
            var emailValidation = validationService.ValidateEmail(request.Email);
            if (!emailValidation.IsValid)
            {
                return Results.BadRequest(new { Message = "Validation failed", Errors = emailValidation.Errors });
            }

            var passwordValidation = validationService.ValidatePassword(request.Password);
            if (!passwordValidation.IsValid)
            {
                return Results.BadRequest(new { Message = "Validation failed", Errors = passwordValidation.Errors });
            }

            if (await userManager.FindByEmailAsync(request.Email) != null)
            {
                return Results.BadRequest(new { Message = "Email already exists" });
            }

            var user = new ApplicationUser
            {
                UserName = request.Email,
                Email = request.Email,
                FirstName = request.FirstName,
                LastName = request.LastName
            };

            var result = await userManager.CreateAsync(user, request.Password);

            if (!result.Succeeded)
            {
                return Results.BadRequest(new { Message = "Registration failed", Errors = result.Errors.Select(e => e.Description) });
            }

            // Generate email confirmation token
            var token = await userManager.GenerateEmailConfirmationTokenAsync(user);
            await emailService.SendEmailConfirmationAsync(user.Email, token);

            return Results.Ok(new { Message = "Registration successful. Please check your email to confirm your account." });
        })
        .WithName("Register")
        .WithSummary("Register a new user account")
        .WithOpenApi();

        // Login endpoint
        authGroup.MapPost("/login", async (LoginRequest request, UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, ITokenService tokenService) =>
        {
            var user = await userManager.FindByEmailAsync(request.Email);
            if (user == null)
            {
                return Results.BadRequest(new { Message = "Invalid email or password" });
            }

            var result = await signInManager.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: true);

            if (!result.Succeeded)
            {
                if (result.IsLockedOut)
                {
                    return Results.BadRequest(new { Message = "Account locked due to multiple failed attempts. Please try again later." });
                }
                if (result.IsNotAllowed)
                {
                    return Results.BadRequest(new { Message = "Email not confirmed. Please check your email and confirm your account." });
                }
                return Results.BadRequest(new { Message = "Invalid email or password" });
            }

            var jwtToken = await tokenService.GenerateJwtTokenAsync(user);
            var refreshToken = tokenService.GenerateRefreshToken();

            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);
            await userManager.UpdateAsync(user);

            return Results.Ok(new LoginResponse
            {
                AccessToken = jwtToken,
                RefreshToken = refreshToken,
                ExpiresIn = 3600,
                User = new UserInfo
                {
                    Id = user.Id,
                    Email = user.Email!,
                    FirstName = user.FirstName,
                    LastName = user.LastName
                }
            });
        })
        .WithName("Login")
        .WithSummary("User login with email and password")
        .WithOpenApi();

        // Refresh token endpoint
        authGroup.MapPost("/refresh", async (DTOs.RefreshTokenRequest request, UserManager<ApplicationUser> userManager, ITokenService tokenService) =>
        {
            var user = await userManager.Users.FirstOrDefaultAsync(u => u.RefreshToken == request.RefreshToken);
            
            if (user == null || user.RefreshTokenExpiryTime <= DateTime.UtcNow)
            {
                return Results.BadRequest(new { Message = "Invalid or expired refresh token" });
            }

            var newJwtToken = await tokenService.GenerateJwtTokenAsync(user);
            var newRefreshToken = tokenService.GenerateRefreshToken();

            user.RefreshToken = newRefreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);
            await userManager.UpdateAsync(user);

            return Results.Ok(new LoginResponse
            {
                AccessToken = newJwtToken,
                RefreshToken = newRefreshToken,
                ExpiresIn = 3600
            });
        })
        .WithName("RefreshToken")
        .WithSummary("Refresh JWT access token")
        .WithOpenApi();

        // Email confirmation endpoint
        authGroup.MapGet("/confirm-email", async (string userId, string token, UserManager<ApplicationUser> userManager) =>
        {
            var user = await userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return Results.BadRequest(new { Message = "Invalid user" });
            }

            var result = await userManager.ConfirmEmailAsync(user, token);
            if (result.Succeeded)
            {
                return Results.Ok(new { Message = "Email confirmed successfully! You can now log in." });
            }

            return Results.BadRequest(new { Message = "Email confirmation failed", Errors = result.Errors.Select(e => e.Description) });
        })
        .WithName("ConfirmEmail")
        .WithSummary("Confirm user email address")
        .WithOpenApi();

        // Forgot password endpoint
        authGroup.MapPost("/forgot-password", async (DTOs.ForgotPasswordRequest request, UserManager<ApplicationUser> userManager, IEmailService emailService) =>
        {
            var user = await userManager.FindByEmailAsync(request.Email);
            if (user == null)
            {
                // Don't reveal that the user does not exist
                return Results.Ok(new { Message = "If the email exists, a password reset link has been sent." });
            }

            var token = await userManager.GeneratePasswordResetTokenAsync(user);
            await emailService.SendPasswordResetAsync(user.Email!, token);

            return Results.Ok(new { Message = "If the email exists, a password reset link has been sent." });
        })
        .WithName("ForgotPassword")
        .WithSummary("Request password reset")
        .WithOpenApi();

        // Reset password endpoint
        authGroup.MapPost("/reset-password", async (DTOs.ResetPasswordRequest request, UserManager<ApplicationUser> userManager) =>
        {
            var user = await userManager.FindByEmailAsync(request.Email);
            if (user == null)
            {
                return Results.BadRequest(new { Message = "Invalid request" });
            }

            var result = await userManager.ResetPasswordAsync(user, request.Token, request.NewPassword);
            if (result.Succeeded)
            {
                return Results.Ok(new { Message = "Password reset successfully" });
            }

            return Results.BadRequest(new { Message = "Password reset failed", Errors = result.Errors.Select(e => e.Description) });
        })
        .WithName("ResetPassword")
        .WithSummary("Reset password with token")
        .WithOpenApi();

        // Change password endpoint
        authGroup.MapPost("/change-password", async (DTOs.ChangePasswordRequest request, UserManager<ApplicationUser> userManager, ClaimsPrincipal user) =>
        {
            var userId = user.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var appUser = await userManager.FindByIdAsync(userId!);

            if (appUser == null)
            {
                return Results.BadRequest(new { Message = "User not found" });
            }

            var result = await userManager.ChangePasswordAsync(appUser, request.CurrentPassword, request.NewPassword);
            if (result.Succeeded)
            {
                return Results.Ok(new { Message = "Password changed successfully" });
            }

            return Results.BadRequest(new { Message = "Password change failed", Errors = result.Errors.Select(e => e.Description) });
        })
        .RequireAuthorization()
        .WithName("ChangePassword")
        .WithSummary("Change password (requires authentication)")
        .WithOpenApi();

        // User profile endpoint
        authGroup.MapGet("/profile", async (UserManager<ApplicationUser> userManager, ClaimsPrincipal user) =>
        {
            var userId = user.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var appUser = await userManager.FindByIdAsync(userId!);

            if (appUser == null)
            {
                return Results.NotFound(new { Message = "User not found" });
            }

            return Results.Ok(new UserInfo
            {
                Id = appUser.Id,
                Email = appUser.Email!,
                FirstName = appUser.FirstName,
                LastName = appUser.LastName
            });
        })
        .RequireAuthorization()
        .WithName("GetProfile")
        .WithSummary("Get user profile (requires authentication)")
        .WithOpenApi();

        // Logout endpoint
        authGroup.MapPost("/logout", async (UserManager<ApplicationUser> userManager, ClaimsPrincipal user) =>
        {
            var userId = user.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var appUser = await userManager.FindByIdAsync(userId!);

            if (appUser != null)
            {
                appUser.RefreshToken = null;
                appUser.RefreshTokenExpiryTime = DateTime.UtcNow;
                await userManager.UpdateAsync(appUser);
            }

            return Results.Ok(new { Message = "Logged out successfully" });
        })
        .RequireAuthorization()
        .WithName("Logout")
        .WithSummary("Logout user (requires authentication)")
        .WithOpenApi();

        // Google SSO endpoint
        authGroup.MapGet("/google", () =>
        {
            var properties = new AuthenticationProperties
            {
                RedirectUri = "/api/auth/google-callback"
            };
            return Results.Challenge(properties, new[] { GoogleDefaults.AuthenticationScheme });
        })
        .WithName("GoogleSSO")
        .WithSummary("Initiate Google OAuth authentication")
        .WithOpenApi();

        // Google callback endpoint
        authGroup.MapGet("/google-callback", async (HttpContext context, UserManager<ApplicationUser> userManager, ITokenService tokenService) =>
        {
            var result = await context.AuthenticateAsync(GoogleDefaults.AuthenticationScheme);
            if (!result.Succeeded)
            {
                return Results.BadRequest(new { Message = "Google authentication failed" });
            }

            var email = result.Principal?.FindFirst(ClaimTypes.Email)?.Value;
            var firstName = result.Principal?.FindFirst(ClaimTypes.GivenName)?.Value;
            var lastName = result.Principal?.FindFirst(ClaimTypes.Surname)?.Value;

            if (string.IsNullOrEmpty(email))
            {
                return Results.BadRequest(new { Message = "Email not provided by Google" });
            }

            var user = await userManager.FindByEmailAsync(email);
            if (user == null)
            {
                user = new ApplicationUser
                {
                    UserName = email,
                    Email = email,
                    FirstName = firstName ?? "",
                    LastName = lastName ?? "",
                    EmailConfirmed = true
                };

                var createResult = await userManager.CreateAsync(user);
                if (!createResult.Succeeded)
                {
                    return Results.BadRequest(new { Message = "Failed to create user account", Errors = createResult.Errors.Select(e => e.Description) });
                }
            }

            var jwtToken = await tokenService.GenerateJwtTokenAsync(user);
            var refreshToken = tokenService.GenerateRefreshToken();

            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);
            await userManager.UpdateAsync(user);

            return Results.Ok(new LoginResponse
            {
                AccessToken = jwtToken,
                RefreshToken = refreshToken,
                ExpiresIn = 3600,
                User = new UserInfo
                {
                    Id = user.Id,
                    Email = user.Email!,
                    FirstName = user.FirstName,
                    LastName = user.LastName
                }
            });
        })
        .WithName("GoogleCallback")
        .WithSummary("Google OAuth callback")
        .WithOpenApi();
    }
}