using System.ComponentModel.DataAnnotations;

namespace AuthMicroservice.Models
{
    public class UserSession
    {
        public int Id { get; set; }
        
        [Required]
        public string UserId { get; set; } = string.Empty;
        
        public string? DeviceInfo { get; set; }
        public string? IpAddress { get; set; }
        public string? UserAgent { get; set; }
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime? LastActivityAt { get; set; }
        public bool IsActive { get; set; } = true;

        // Navigation property
        public virtual ApplicationUser User { get; set; } = null!;
    }
}