namespace AuthMicroservice.Services;

public interface IEmailService
{
    Task SendEmailConfirmationAsync(string email, string token);
    Task SendPasswordResetAsync(string email, string token);
    Task SendWelcomeEmailAsync(string email, string firstName);
    Task SendPasswordResetEmailAsync(string toEmail, string resetToken);
}

public class EmailService : IEmailService
{
    private readonly IConfiguration _configuration;
    private readonly ILogger<EmailService> _logger;

    public EmailService(IConfiguration configuration, ILogger<EmailService> logger)
    {
        _configuration = configuration;
        _logger = logger;
    }

    public async Task SendEmailConfirmationAsync(string email, string token)
    {
        var confirmationLink = $"{_configuration["AppUrl"] ?? "https://localhost:5001"}/api/auth/confirm-email?userId={Uri.EscapeDataString(email)}&token={Uri.EscapeDataString(token)}";
        
        var subject = "Confirm Your Email Address";
        var body = $@"
            <h2>Confirm Your Email Address</h2>
            <p>Thank you for registering! Please click the link below to confirm your email address:</p>
            <p><a href='{confirmationLink}' style='background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px;'>Confirm Email</a></p>
            <p>If the button doesn't work, copy and paste this link into your browser:</p>
            <p>{confirmationLink}</p>
            <p>If you didn't create an account, please ignore this email.</p>";

        await SendEmailAsync(email, subject, body);
    }

    public async Task SendPasswordResetAsync(string email, string token)
    {
        var resetLink = $"{_configuration["AppUrl"] ?? "https://localhost:5001"}/reset-password?email={Uri.EscapeDataString(email)}&token={Uri.EscapeDataString(token)}";
        
        var subject = "Reset Your Password";
        var body = $@"
            <h2>Reset Your Password</h2>
            <p>We received a request to reset your password. Click the link below to create a new password:</p>
            <p><a href='{resetLink}' style='background-color: #dc3545; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px;'>Reset Password</a></p>
            <p>If the button doesn't work, copy and paste this link into your browser:</p>
            <p>{resetLink}</p>
            <p>This link will expire in 24 hours for security reasons.</p>
            <p>If you didn't request a password reset, please ignore this email.</p>";

        await SendEmailAsync(email, subject, body);
    }

    public async Task SendWelcomeEmailAsync(string email, string firstName)
    {
        var subject = "Welcome to Our Platform!";
        var body = $@"
            <h1>Welcome, {firstName}! 🎉</h1>
            <p>Thank you for joining our platform! We're excited to have you on board.</p>
            <p>Your account has been successfully created and verified. You can now access all features of our platform.</p>
            <p>If you have any questions or need assistance, feel free to contact our support team.</p>
            <p>Welcome to the community!</p>
            <p>Best regards,<br>The Team</p>";

        await SendEmailAsync(email, subject, body);
    }
    
    public async Task SendPasswordResetEmailAsync(string toEmail, string resetToken)
    {
        // TODO: Replace with actual email sending logic
        Console.WriteLine($"Sending password reset email to {toEmail} with token {resetToken}");
        await Task.CompletedTask;
    }

    private async Task SendEmailAsync(string to, string subject, string body)
    {
        try
        {
            // For development, just log the email
            _logger.LogInformation("Email would be sent to {Email} with subject: {Subject}", to, subject);
            _logger.LogInformation("Email body: {Body}", body);

            // TODO: Implement actual email sending with your preferred provider (SendGrid, AWS SES, etc.)
            await Task.CompletedTask;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send email to {Email}", to);
            throw;
        }
    }
}