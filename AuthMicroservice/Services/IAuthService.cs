using AuthMicroservice.Middleware.Data;
using AuthMicroservice.Models;
using AuthMicroservice.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

// ==================== AUTH SERVICE INTERFACE ====================
public interface IAuthService
{
    Task<AuthResult<TokenResponse>> SignUpAsync(SignUpRequest request);
    Task<AuthResult<TokenResponse>> SignInAsync(SignInRequest request);
    Task<AuthResult<TokenResponse>> RefreshTokenAsync(RefreshTokenRequest request);
    Task LogoutAsync(string refreshToken);
    Task ForgotPasswordAsync(string email);
    Task<AuthResult<object>> ResetPasswordAsync(ResetPasswordRequest request);
    Task<AuthResult<object>> ChangePasswordAsync(string userId, ChangePasswordRequest request);
    Task<UserInfo?> GetUserProfileAsync(string userId);
    Task<AuthResult<UserInfo>> UpdateProfileAsync(string userId, UpdateProfileRequest request);
    Task<AuthResult<TokenResponse>> HandleExternalLoginAsync(string provider, HttpContext context);
    Task<UserInfo?> GetUserInfoAsync(string userId);
}

// ==================== AUTH SERVICE IMPLEMENTATION ====================
public class AuthService : IAuthService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly IJwtTokenService _tokenService;
    private readonly IEmailService _emailService;
    private readonly AuthDbContext _context;

    public AuthService(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        IJwtTokenService tokenService,
        IEmailService emailService,
        AuthDbContext context)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _tokenService = tokenService;
        _emailService = emailService;
        _context = context;
    }

    public async Task<AuthResult<TokenResponse>> SignUpAsync(SignUpRequest request)
    {
        try
        {
            var existingUser = await _userManager.FindByEmailAsync(request.Email);
            if (existingUser != null)
            {
                return new AuthResult<TokenResponse>
                {
                    Success = false,
                    Message = "User already exists with this email",
                    Errors = ["Email already registered"]
                };
            }

            var user = new ApplicationUser
            {
                UserName = request.Email,
                Email = request.Email,
                FirstName = request.FirstName,
                LastName = request.LastName,
                PhoneNumber = request.PhoneNumber,
                CreatedAt = DateTime.UtcNow
            };

            var result = await _userManager.CreateAsync(user, request.Password);
            if (!result.Succeeded)
            {
                return new AuthResult<TokenResponse>
                {
                    Success = false,
                    Message = "Failed to create user",
                    Errors = result.Errors.Select(e => e.Description).ToList()
                };
            }

            // Assign default role
            await _userManager.AddToRoleAsync(user, "User");

            // Generate tokens
            var tokenResponse = await GenerateTokenResponseAsync(user);

            return new AuthResult<TokenResponse>
            {
                Success = true,
                Message = "User created successfully",
                Data = tokenResponse
            };
        }
        catch (Exception ex)
        {
            return new AuthResult<TokenResponse>
            {
                Success = false,
                Message = "An error occurred during registration",
                Errors = [ex.Message]
            };
        }
    }

    public async Task<AuthResult<TokenResponse>> SignInAsync(SignInRequest request)
    {
        try
        {
            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null)
            {
                return new AuthResult<TokenResponse>
                {
                    Success = false,
                    Message = "Invalid credentials"
                };
            }

            var result = await _signInManager.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: true);
            if (!result.Succeeded)
            {
                var message = result.IsLockedOut ? "Account is locked out" : "Invalid credentials";
                return new AuthResult<TokenResponse>
                {
                    Success = false,
                    Message = message
                };
            }

            // Update last login
            user.LastLoginAt = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);

            var tokenResponse = await GenerateTokenResponseAsync(user);

            return new AuthResult<TokenResponse>
            {
                Success = true,
                Message = "Login successful",
                Data = tokenResponse
            };
        }
        catch (Exception ex)
        {
            return new AuthResult<TokenResponse>
            {
                Success = false,
                Message = "An error occurred during login",
                Errors = [ex.Message]
            };
        }
    }

    public async Task<AuthResult<TokenResponse>> RefreshTokenAsync(RefreshTokenRequest request)
    {
        try
        {
            var refreshToken = await _context.RefreshTokens
                //.Include(rt => rt.User)
                .FirstOrDefaultAsync(rt => rt.Token == request.RefreshToken && rt.IsActive);

            if (refreshToken == null)
            {
                return new AuthResult<TokenResponse>
                {
                    Success = false,
                    Message = "Invalid refresh token"
                };
            }

            // Revoke old refresh token
            refreshToken.RevokedAt = DateTime.UtcNow;

            // Generate new tokens
            //var tokenResponse = await GenerateTokenResponseAsync(refreshToken.User);

            await _context.SaveChangesAsync();

            return new AuthResult<TokenResponse>
            {
                Success = true,
                Message = "Token refreshed successfully",
                //Data = tokenResponse
            };
        }
        catch (Exception ex)
        {
            return new AuthResult<TokenResponse>
            {
                Success = false,
                Message = "An error occurred during token refresh",
                Errors = [ex.Message]
            };
        }
    }

    public async Task LogoutAsync(string refreshToken)
    {
        var token = await _context.RefreshTokens
            .FirstOrDefaultAsync(rt => rt.Token == refreshToken);

        if (token != null)
        {
            token.RevokedAt = DateTime.UtcNow;
            await _context.SaveChangesAsync();
        }
    }

    public async Task ForgotPasswordAsync(string email)
    {
        var user = await _userManager.FindByEmailAsync(email);
        if (user != null)
        {
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            await _emailService.SendPasswordResetEmailAsync(user.Email!, token);
        }
        // Always return success to prevent email enumeration
    }

    public async Task<AuthResult<object>> ResetPasswordAsync(ResetPasswordRequest request)
    {
        try
        {
            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null)
            {
                return new AuthResult<object>
                {
                    Success = false,
                    Message = "Invalid reset request"
                };
            }

            var result = await _userManager.ResetPasswordAsync(user, request.Token, request.NewPassword);
            if (!result.Succeeded)
            {
                return new AuthResult<object>
                {
                    Success = false,
                    Message = "Failed to reset password",
                    Errors = result.Errors.Select(e => e.Description).ToList()
                };
            }

            return new AuthResult<object>
            {
                Success = true,
                Message = "Password reset successfully"
            };
        }
        catch (Exception ex)
        {
            return new AuthResult<object>
            {
                Success = false,
                Message = "An error occurred during password reset",
                Errors = [ex.Message]
            };
        }
    }

    public async Task<AuthResult<object>> ChangePasswordAsync(string userId, ChangePasswordRequest request)
    {
        try
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return new AuthResult<object>
                {
                    Success = false,
                    Message = "User not found"
                };
            }

            var result = await _userManager.ChangePasswordAsync(user, request.CurrentPassword, request.NewPassword);
            if (!result.Succeeded)
            {
                return new AuthResult<object>
                {
                    Success = false,
                    Message = "Failed to change password",
                    Errors = result.Errors.Select(e => e.Description).ToList()
                };
            }

            return new AuthResult<object>
            {
                Success = true,
                Message = "Password changed successfully"
            };
        }
        catch (Exception ex)
        {
            return new AuthResult<object>
            {
                Success = false,
                Message = "An error occurred during password change",
                Errors = [ex.Message]
            };
        }
    }

    public async Task<UserInfo?> GetUserProfileAsync(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null) return null;

        var roles = await _userManager.GetRolesAsync(user);

        return new UserInfo
        {
            Id = user.Id,
            Email = user.Email!,
            FirstName = user.FirstName,
            LastName = user.LastName,
            PhoneNumber = user.PhoneNumber,
            Roles = roles.ToList()
        };
    }

    public async Task<AuthResult<UserInfo>> UpdateProfileAsync(string userId, UpdateProfileRequest request)
    {
        try
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return new AuthResult<UserInfo>
                {
                    Success = false,
                    Message = "User not found"
                };
            }

            if (!string.IsNullOrEmpty(request.FirstName))
                user.FirstName = request.FirstName;

            if (!string.IsNullOrEmpty(request.LastName))
                user.LastName = request.LastName;

            if (!string.IsNullOrEmpty(request.PhoneNumber))
                user.PhoneNumber = request.PhoneNumber;

            user.UpdatedAt = DateTime.UtcNow;

            var result = await _userManager.UpdateAsync(user);
            if (!result.Succeeded)
            {
                return new AuthResult<UserInfo>
                {
                    Success = false,
                    Message = "Failed to update profile",
                    Errors = result.Errors.Select(e => e.Description).ToList()
                };
            }

            var userInfo = await GetUserProfileAsync(userId);
            return new AuthResult<UserInfo>
            {
                Success = true,
                Message = "Profile updated successfully",
                Data = userInfo
            };
        }
        catch (Exception ex)
        {
            return new AuthResult<UserInfo>
            {
                Success = false,
                Message = "An error occurred during profile update",
                Errors = [ex.Message]
            };
        }
    }

    public async Task<AuthResult<TokenResponse>> HandleExternalLoginAsync(string provider, HttpContext context)
    {
        try
        {
            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                return new AuthResult<TokenResponse>
                {
                    Success = false,
                    Message = "External login information not found"
                };
            }

            var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false);

            if (result.Succeeded)
            {
                // User exists, sign them in
                var user = await _userManager.FindByLoginAsync(info.LoginProvider, info.ProviderKey);
                var tokenResponse = await GenerateTokenResponseAsync(user!);

                return new AuthResult<TokenResponse>
                {
                    Success = true,
                    Message = "External login successful",
                    Data = tokenResponse
                };
            }
            else
            {
                // User doesn't exist, create new user
                var email = info.Principal.FindFirstValue(ClaimTypes.Email);
                var firstName = info.Principal.FindFirstValue(ClaimTypes.GivenName) ?? "";
                var lastName = info.Principal.FindFirstValue(ClaimTypes.Surname) ?? "";

                if (string.IsNullOrEmpty(email))
                {
                    return new AuthResult<TokenResponse>
                    {
                        Success = false,
                        Message = "Email not provided by external provider"
                    };
                }

                var user = new ApplicationUser
                {
                    UserName = email,
                    Email = email,
                    FirstName = firstName,
                    LastName = lastName,
                    EmailConfirmed = true,
                    CreatedAt = DateTime.UtcNow
                };

                var createResult = await _userManager.CreateAsync(user);
                if (createResult.Succeeded)
                {
                    await _userManager.AddToRoleAsync(user, "User");
                    await _userManager.AddLoginAsync(user, info);

                    var tokenResponse = await GenerateTokenResponseAsync(user);

                    return new AuthResult<TokenResponse>
                    {
                        Success = true,
                        Message = "Account created and logged in successfully",
                        Data = tokenResponse
                    };
                }
                else
                {
                    return new AuthResult<TokenResponse>
                    {
                        Success = false,
                        Message = "Failed to create user account",
                        Errors = createResult.Errors.Select(e => e.Description).ToList()
                    };
                }
            }
        }
        catch (Exception ex)
        {
            return new AuthResult<TokenResponse>
            {
                Success = false,
                Message = "An error occurred during external login",
                Errors = [ex.Message]
            };
        }
    }

    public async Task<UserInfo?> GetUserInfoAsync(string userId)
    {
        return await GetUserProfileAsync(userId);
    }

    private async Task<TokenResponse> GenerateTokenResponseAsync(ApplicationUser user)
    {
        var roles = await _userManager.GetRolesAsync(user);
        var token = _tokenService.GenerateAccessToken(user, roles);
        var refreshToken = _tokenService.GenerateRefreshToken();

        // Save refresh token to database
        var refreshTokenEntity = new RefreshToken
        {
            Token = refreshToken,
            UserId = user.Id,
            ExpiresAt = DateTime.UtcNow.AddDays(30),
            CreatedAt = DateTime.UtcNow
        };

        _context.RefreshTokens.Add(refreshTokenEntity);
        await _context.SaveChangesAsync();

        return new TokenResponse
        {
            Token = token,
            RefreshToken = refreshToken,
            Expires = DateTime.UtcNow.AddMinutes(15), // Access token expires in 15 minutes
            User = new UserInfo
            {
                Id = user.Id,
                Email = user.Email!,
                FirstName = user.FirstName,
                LastName = user.LastName,
                PhoneNumber = user.PhoneNumber,
                Roles = roles.ToList()
            }
        };
    }
}
/*
using AuthMicroservice.Models;

namespace AuthMicroservice.Services
{
    public interface IAuthService
    {
        Task<AuthResult<TokenResponse>> SignUpAsync(SignUpRequest request);
        Task<AuthResult<TokenResponse>> SignInAsync(SignInRequest request);
        Task<AuthResult<TokenResponse>> RefreshTokenAsync(RefreshTokenRequest request);
        Task LogoutAsync(string refreshToken);
        Task ForgotPasswordAsync(string email);
        Task<AuthResult<object>> ResetPasswordAsync(ResetPasswordRequest request);
        Task<AuthResult<object>> ChangePasswordAsync(string userId, ChangePasswordRequest request);
        Task<UserInfo?> GetUserProfileAsync(string userId);
        Task<AuthResult<UserInfo>> UpdateProfileAsync(string userId, UpdateProfileRequest request);
        Task<AuthResult<TokenResponse>> HandleExternalLoginAsync(string provider, HttpContext context);
        Task<UserInfo?> GetUserInfoAsync(string userId);
    }
}
*/
