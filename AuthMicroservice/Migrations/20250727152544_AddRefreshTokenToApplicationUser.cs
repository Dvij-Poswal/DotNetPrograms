using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AuthMicroservice.Migrations
{
    /// <inheritdoc />
    public partial class AddRefreshTokenToApplicationUser : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.UpdateData(
                table: "AspNetUsers",
                keyColumn: "Id",
                keyValue: "admin-user-id",
                column: "UpdatedAt",
                value: new DateTime(2025, 7, 27, 15, 25, 39, 841, DateTimeKind.Utc).AddTicks(2042));
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.UpdateData(
                table: "AspNetUsers",
                keyColumn: "Id",
                keyValue: "admin-user-id",
                column: "UpdatedAt",
                value: new DateTime(2025, 7, 27, 9, 29, 50, 444, DateTimeKind.Utc).AddTicks(8710));
        }
    }
}
