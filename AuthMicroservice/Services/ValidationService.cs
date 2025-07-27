using System.Text.RegularExpressions;

namespace AuthMicroservice.Services;

public interface IValidationService
{
    ValidationResult ValidatePassword(string password);
    ValidationResult ValidateEmail(string email);
}

public class ValidationService : IValidationService
{
    public ValidationResult ValidatePassword(string password)
    {
        var result = new ValidationResult();

        if (string.IsNullOrWhiteSpace(password))
        {
            result.AddError("Password is required");
            return result;
        }

        if (password.Length < 8)
            result.AddError("Password must be at least 8 characters long");

        if (!Regex.IsMatch(password, @"[a-z]"))
            result.AddError("Password must contain at least one lowercase letter");

        if (!Regex.IsMatch(password, @"[A-Z]"))
            result.AddError("Password must contain at least one uppercase letter");

        if (!Regex.IsMatch(password, @"\d"))
            result.AddError("Password must contain at least one digit");

        if (!Regex.IsMatch(password, @"[@$!%*?&]"))
            result.AddError("Password must contain at least one special character");

        return result;
    }

    public ValidationResult ValidateEmail(string email)
    {
        var result = new ValidationResult();

        if (string.IsNullOrWhiteSpace(email))
        {
            result.AddError("Email is required");
            return result;
        }

        if (!Regex.IsMatch(email, @"^[^@\s]+@[^@\s]+\.[^@\s]+$", RegexOptions.IgnoreCase))
        {
            result.AddError("Invalid email format");
        }

        return result;
    }
}

public class ValidationResult
{
    public bool IsValid => !Errors.Any();
    public List<string> Errors { get; } = new();

    public void AddError(string error)
    {
        Errors.Add(error);
    }
}