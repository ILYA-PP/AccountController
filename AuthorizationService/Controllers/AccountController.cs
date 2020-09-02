using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using AuthorizationService.Models;
using Microsoft.CodeAnalysis.Options;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Authorization;
using System.Text;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.EntityFrameworkCore;

namespace AuthorizationService.Models
{
    [ApiController]
    public class AccountController : ControllerBase
    {
        private TokenSettings _tokenSettings;
        private AuthDbContext _dbContext;

        public AccountController(TokenSettings tokenSettings, AuthDbContext dbContext)
        {
            _tokenSettings = tokenSettings;
            _dbContext = dbContext;
        }
        //аналогично value controller
        [HttpGet("/user/info")]
        [Authorize]
        [ProducesResponseType(typeof(User), StatusCodes.Status200OK)]
        public IActionResult GetUserInfo()
        {
            var login = HttpContext.User.Claims.FirstOrDefault(x => x.Type == "login");
            User user = new User() { Login = "fege", Password = "bgkefkjv" };
            return Ok(user);
        }
        /// <summary>
        /// Подтверждение авторизации пользователя
        /// </summary>
        /// <param name="model"></param>
        /// <response code="200">Код доступа успешно создан</response>
        /// <response code="400">Неправильный ввод данных</response> 
        [HttpPost("/auth/confirm")]
        public IActionResult Login(string login, string password)
        {
            var user = _dbContext.Users.Include(r => r.RefreshTokens).SingleOrDefault(x => x.Login == login);
            if (user == null)
                return BadRequest(new { Messages = new[] { "Incorrect Login." } });

            // Проверка смс кода из бд
            if (user.Password != password)
                return BadRequest(new { Messages = new[] { "Incorrect Password." } });

            // Создание отпечатка
            string fgp = GenRandomString("QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm", 50);
            HttpContext.Response.Cookies.Append("Fgp", fgp,
                new CookieOptions
                {
                    Expires = new DateTimeOffset(DateTime.UtcNow.AddDays(90)),
                    HttpOnly = true,
                    SameSite = SameSiteMode.Strict
                });

            var refreshToken = generateRefreshToken(user.Id);
            _dbContext.RefreshTokens.Add(refreshToken);
            _dbContext.SaveChanges();

            HttpContext.Response.Cookies.Append("RefreshToken", refreshToken.Token,
                new CookieOptions
                {
                    Expires = new DateTimeOffset(DateTime.UtcNow.AddDays(30)),
                    HttpOnly = true,
                    SameSite = SameSiteMode.Strict
                });

            return Ok(new { token = IssueToken(login, fgp) });
        }

        /// <summary>
        /// Обновить токен
        /// </summary>
        /// <response code="200">API токен</response>
        /// <response code="401">Неверный RefreshToken</response> 
        [HttpPost("/auth/refreshToken")]
        public IActionResult RefreshToken()
        {
            var token = Request.Cookies["refreshToken"];
            var fgp = Request.Cookies["Fgp"];

            //var user = _dbContext.users.SingleOrDefault(u => u.RefreshTokens.Any(t => t.Token == token)); ;
            //if (user == null)
            //    return Unauthorized(new { Messages = new[] { "Invalid token." } });

            var refreshToken = _dbContext.RefreshTokens.Include(t => t.User).FirstOrDefault(t => t.Token == token);
            if (refreshToken == null || !refreshToken.IsActive)
                return Unauthorized(new { Messages = new[] { "Invalid token." } });

            var newRefreshToken = generateRefreshToken(refreshToken.UserId);
            refreshToken.Revoked = DateTime.UtcNow;
            refreshToken.ReplacedByToken = newRefreshToken.Token;
            _dbContext.RefreshTokens.Add(newRefreshToken);
            _dbContext.SaveChanges();

            HttpContext.Response.Cookies.Append("RefreshToken", newRefreshToken.Token,
                new CookieOptions
                {
                    Expires = new DateTimeOffset(DateTime.UtcNow.AddDays(30)),
                    HttpOnly = true,
                    SameSite = SameSiteMode.Strict
                });

            return Ok(new { token = IssueToken(newRefreshToken.User.Login, fgp) });
        }

        /// <summary>
        /// Разлогиниться 
        /// </summary>
        /// <response code="200">Успешный ответ</response>
        /// <response code="400">Неверный RefreshToken</response>
        /// <response code="401">Пользователь не аутентифицирован</response>
        [HttpPost("/user/logout")]
        [Authorize]
        public IActionResult Logout()
        {
            var token = Request.Cookies["refreshToken"];

            if (string.IsNullOrEmpty(token))
                return BadRequest(new { message = "RefreshToken is required" });

            var refreshToken = _dbContext.RefreshTokens.Include(t => t.User).FirstOrDefault(t => t.Token == token);
            if (refreshToken == null)
                return BadRequest(new { message = "RefreshToken not found" });

            refreshToken.Revoked = DateTime.UtcNow;
            _dbContext.Update(refreshToken);
            _dbContext.SaveChanges();
            return Ok();
        }
        private string IssueToken(string phone, string fgp)
        {

            var claims = new Dictionary<string, object>
            {
                { "phone", phone },
                { "fgp", ComputeSha256Hash(fgp) },
            };

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Audience = _tokenSettings.Audience,
                Issuer = _tokenSettings.Issuer,
                Claims = claims,
                SigningCredentials = new SigningCredentials(_tokenSettings.GetSecurityKey(), SecurityAlgorithms.RsaSha256),
                EncryptingCredentials = new X509EncryptingCredentials(_tokenSettings.GetCertificate()),
                Expires = DateTime.Now.AddMinutes(15),
                NotBefore = DateTime.Now
            };
            string token = new JwtSecurityTokenHandler().CreateEncodedJwt(tokenDescriptor);

            return token;
        }

        private string GenRandomString(string Alphabet, int Length)
        {
            Random rnd = new Random();
            StringBuilder sb = new StringBuilder(Length - 1);
            int Position;

            for (int i = 0; i < Length; i++)
            {
                Position = rnd.Next(0, Alphabet.Length - 1);
                sb.Append(Alphabet[Position]);
            }
            return sb.ToString();
        }

        private string ComputeSha256Hash(string rawData)
        {
            using (SHA256 sha256Hash = SHA256.Create())
            {
                byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(rawData));
                StringBuilder builder = new StringBuilder();
                for (int i = 0; i < bytes.Length; i++)
                {
                    builder.Append(bytes[i].ToString("x2"));
                }
                return builder.ToString();
            }
        }

        private RefreshToken generateRefreshToken(int userId)
        {
            using (var rngCryptoServiceProvider = new RNGCryptoServiceProvider())
            {
                var randomBytes = new byte[64];
                rngCryptoServiceProvider.GetBytes(randomBytes);
                return new RefreshToken
                {
                    Token = Convert.ToBase64String(randomBytes),
                    Expires = DateTime.UtcNow.AddDays(30),
                    Created = DateTime.UtcNow,
                    UserId = userId,
                };
            }
        }
    }
}