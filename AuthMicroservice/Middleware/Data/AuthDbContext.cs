using AuthMicroservice.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System;

namespace AuthMicroservice.Middleware.Data
{
    public class AuthDbContext : IdentityDbContext<ApplicationUser>
    {
        private const string AdminRoleId = "admin-role-id";
        private const string UserRoleId = "user-role-id";
        private const string AdminUserId = "admin-user-id";

        public AuthDbContext(DbContextOptions<AuthDbContext> options) : base(options) { }

        public DbSet<RefreshToken> RefreshTokens { get; set; }
        public DbSet<UserSession> UserSessions { get; set; }
        public DbSet<AuditLog> AuditLogs { get; set; }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            ConfigureApplicationUser(builder);
            ConfigureRefreshToken(builder);
            ConfigureUserSession(builder);
            ConfigureAuditLog(builder);
            SeedRolesAndAdmin(builder);
        }

        private void ConfigureApplicationUser(ModelBuilder builder)
        {
            builder.Entity<ApplicationUser>(entity =>
            {
                entity.Property(e => e.FirstName).IsRequired().HasMaxLength(100);
                entity.Property(e => e.LastName).IsRequired().HasMaxLength(100);
                entity.Property(e => e.CreatedAt).HasDefaultValueSql("GETUTCDATE()");
                entity.HasIndex(e => e.Email).IsUnique();
            });
        }

        private void ConfigureRefreshToken(ModelBuilder builder)
        {
            builder.Entity<RefreshToken>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.Token).IsRequired().HasMaxLength(500);
                entity.Property(e => e.CreatedAt).HasDefaultValue(new DateTime(2023, 01, 01));
                entity.HasIndex(e => e.Token).IsUnique();
                entity.HasIndex(e => e.UserId);

                entity.HasOne(e => e.User)
                      .WithMany(u => u.RefreshTokens)
                      .HasForeignKey(e => e.UserId)
                      .OnDelete(DeleteBehavior.Cascade);
            });
        }

        private void ConfigureUserSession(ModelBuilder builder)
        {
            builder.Entity<UserSession>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.CreatedAt)
                    .HasDefaultValueSql("GETUTCDATE()");
                entity.HasIndex(e => e.UserId);

                entity.HasOne(e => e.User)
                      .WithMany(u => u.UserSessions)
                      .HasForeignKey(e => e.UserId)
                      .OnDelete(DeleteBehavior.Cascade);

            });
        }

        private void ConfigureAuditLog(ModelBuilder builder)
        {
            builder.Entity<AuditLog>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.Action).IsRequired().HasMaxLength(100);
                entity.Property(e => e.Timestamp).HasDefaultValue(new DateTime(2023, 01, 01));
                entity.HasIndex(e => e.UserId);
                entity.HasIndex(e => e.Timestamp);
            });
        }

        private void SeedRolesAndAdmin(ModelBuilder builder)
        {
            builder.Entity<IdentityRole>().HasData(
                new IdentityRole
                {
                    Id = AdminRoleId,
                    Name = "Admin",
                    NormalizedName = "ADMIN",
                    ConcurrencyStamp = "admin-role-concurrency-stamp" // Static value
                },
                new IdentityRole
                {
                    Id = UserRoleId,
                    Name = "User",
                    NormalizedName = "USER",
                    ConcurrencyStamp = "user-role-concurrency-stamp" // Static value
                }
            );

            builder.Entity<ApplicationUser>().HasData(
                new ApplicationUser
                {
                    Id = AdminUserId,
                    UserName = "admin@example.com",
                    NormalizedUserName = "ADMIN@EXAMPLE.COM",
                    Email = "admin@example.com",
                    NormalizedEmail = "ADMIN@EXAMPLE.COM",
                    EmailConfirmed = true,
                    PasswordHash = "AQAAAAEAACcQAAAAEJq0pWvGWTZ9XTF+WyoKXVnKDqlkHDIHRcKRC93Mf5aTJn/N6j7ZwFTK0LUZAA==", // Use secure hash in prod
                    SecurityStamp = "admin-security-stamp", // Static
                    ConcurrencyStamp = "admin-user-concurrency", // Static
                    FirstName = "System",
                    LastName = "Administrator",
                    CreatedAt = new DateTime(2023, 01, 01), // Static
                    IsActive = true
                }
            );

            builder.Entity<IdentityUserRole<string>>().HasData(
                new IdentityUserRole<string>
                {
                    RoleId = AdminRoleId,
                    UserId = AdminUserId
                }
            );
        }
    }
}
