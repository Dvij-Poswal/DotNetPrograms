using System.ComponentModel.DataAnnotations;

namespace AuthMicroservice.Models
{
    public record SignUpRequest(
        [Required] string Email,
        [Required] string Password,
        [Required] string FirstName,
        [Required] string LastName,
        string? PhoneNumber = null);

    public record SignInRequest(
        [Required] string Email,
        [Required] string Password,
        bool RememberMe = false);

    public record RefreshTokenRequest([Required] string RefreshToken);
    public record LogoutRequest([Required] string RefreshToken);
    public record ForgotPasswordRequest([Required] string Email);
    public record ResetPasswordRequest(
        [Required] string Email,
        [Required] string Token,
        [Required] string NewPassword);

    public record ChangePasswordRequest(
        [Required] string CurrentPassword,
        [Required] string NewPassword);

    public record UpdateProfileRequest(
        string? FirstName,
        string? LastName,
        string? PhoneNumber);

    public record ValidateTokenRequest([Required] string Token);

    public class AuthResult<T>
    {
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
        public T? Data { get; set; }
        public List<string> Errors { get; set; } = new();
    }

    public class TokenResponse
    {
        public string Token { get; set; } = string.Empty;
        public string RefreshToken { get; set; } = string.Empty;
        public DateTime Expires { get; set; }
        public UserInfo User { get; set; } = null!;
    }

    public class UserInfo
    {
        public string Id { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string FirstName { get; set; } = string.Empty;
        public string LastName { get; set; } = string.Empty;
        public string? PhoneNumber { get; set; }
        public List<string> Roles { get; set; } = new();
    }
}