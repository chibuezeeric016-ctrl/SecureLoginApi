using System.ComponentModel.DataAnnotations;
namespace SecureLoginApi.DTOs
{
    public class RefreshTokenDto
    {
        [Required]
        public string RefreshToken { get; set; } = string.Empty;
    }
}
