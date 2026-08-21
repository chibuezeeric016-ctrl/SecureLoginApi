using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Mvc;
using SecureLoginApi.DTOs;
using SecureLoginApi.Models;
using SecureLoginApi.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace SecureLoginApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly AppDbContext _context;
        private readonly JwtSettings _jwtSettings;
        public AuthController(AppDbContext context, JwtSettings jwtSettings)
        {
            _context = context;
            _jwtSettings = jwtSettings;
        }
        [HttpPost("register")]
        public async Task<IActionResult> Register(RegisterDto dto)
        {
            if (await _context.Users.AnyAsync(u => u.Username == dto.Username || u.Email == dto.Email))
            {
                return BadRequest(new { message = "Username already exists." });
            }
            var user = new User
            {
                Username = dto.Username,
                Email = dto.Email,
                PasswordHash = BCrypt.Net.BCrypt.HashPassword(dto.Password),
                Role = "User"
            };
            _context.Users.Add(user);
            await _context.SaveChangesAsync();
            return Ok(new { message = "User registered successfully." });
        }
        [HttpPost("login")]
        public async Task<IActionResult> Login(LoginDto dto)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == dto.Username);

            if (user == null || !BCrypt.Net.BCrypt.Verify(dto.Password, user.PasswordHash))
            {
                return Unauthorized("Invalid username or password.");
            }

            var accessToken = GenerateAccessToken(user);
            var refreshToken = GenerateRefreshToken();


            var refreshTokenEntity = new RefreshToken
            {
                Token = refreshToken,
                ExpiresAt = DateTime.UtcNow.AddDays(7),
                UserId = user.Id
            };
            _context.RefreshTokens.Add(refreshTokenEntity);
            await _context.SaveChangesAsync();


            return Ok(new AuthResponseDto
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken,
                AccessTokenExpires = DateTime.UtcNow.AddMinutes(15)
            });
        }
        private string GenerateAccessToken(User user)
        {
            var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Name, user.Username),
            new Claim(ClaimTypes.Role, user.Role)
        };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Key));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _jwtSettings.Issuer,
                audience: _jwtSettings.Audience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(15),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private string GenerateRefreshToken()
        {
            var randomBytes = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomBytes);
            return Convert.ToBase64String(randomBytes);
        }

        [Authorize]
        [HttpGet("me")]
        public IActionResult Me()
        {
            var username = User.FindFirstValue(ClaimTypes.Name);
            var role = User.FindFirstValue(ClaimTypes.Role);
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            return Ok(new
            {
                Id = userId,
                Username = username,
                Role = role
            });
        }
        [Authorize(Roles = "Admin")]
        [HttpGet("admin-only")]
        public IActionResult AdminOnly()
        {
            return Ok(new { message = "Welcome Admin to Agodi's Secure login Api" });
        }

        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken(RefreshTokenDto dto)
        {
         
          var storedToken = await _context.RefreshTokens
         .Include(rt => rt.User)
         .FirstOrDefaultAsync(rt => rt.Token == dto.RefreshToken);

          if (storedToken == null || storedToken.IsRevoked || storedToken.ExpiresAt < DateTime.UtcNow)
          {
              return Unauthorized("Invalid or expired refresh token.");
          }

        
          storedToken.IsRevoked = true;
          var newAccessToken = GenerateAccessToken(storedToken.User);
          var newRefreshToken = GenerateRefreshToken();

                var newRefreshTokenEntity = new RefreshToken
                {
                    Token = newRefreshToken,
                    ExpiresAt = DateTime.UtcNow.AddDays(7),
                    UserId = storedToken.User.Id
                };

                _context.RefreshTokens.Add(newRefreshTokenEntity);
                await _context.SaveChangesAsync();

                return Ok(new AuthResponseDto
                {
                    AccessToken = newAccessToken,
                    RefreshToken = newRefreshToken,
                    AccessTokenExpires = DateTime.UtcNow.AddMinutes(15)
                });


        }
    }
}







