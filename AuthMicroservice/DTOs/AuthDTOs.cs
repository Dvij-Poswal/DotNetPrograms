using System.ComponentModel.DataAnnotations;

namespace AuthMicroservice.DTOs;

public record RegisterRequest(
    [Required] string Email, 
    [Required] string Password, 
    [Required] string FirstName, 
    [Required] string LastName,
    bool AcceptTerms = true);

public record LoginRequest([Required] string Email, [Required] string Password, bool RememberMe = false);

public record RefreshTokenRequest([Required] string RefreshToken);

public record ForgotPasswordRequest([Required] string Email);

public record ResetPasswordRequest([Required] string Email, [Required] string Token, [Required] string NewPassword);

public record ChangePasswordRequest([Required] string CurrentPassword, [Required] string NewPassword);

public record LoginResponse
{
    public string AccessToken { get; set; } = string.Empty;
    public string RefreshToken { get; set; } = string.Empty;
    public int ExpiresIn { get; set; }
    public UserInfo? User { get; set; }
}

public record UserInfo
{
    public string Id { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string FirstName { get; set; } = string.Empty;
    public string LastName { get; set; } = string.Empty;
}