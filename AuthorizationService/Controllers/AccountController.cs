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

namespace AuthorizationService.Models
{
    [ApiController]
    public class AccountController : ControllerBase
    {
        private TokenSettings _tokenSettings;

        public AccountController(IOptions<TokenSettings> tokenSettings)
        {
            //_tokenSettings = tokenSettings;
        }

        //[HttpGet("/user/info")]
        //[Authorize]
        //[ProducesResponseType(typeof(User), StatusCodes.Status200OK)]
        //public IActionResult GetUserInfo()
        //{
        //    var login = HttpContext.User.Claims.FirstOrDefault(x => x.Type == "login");
        //    //User user = 
        //}
    }
}