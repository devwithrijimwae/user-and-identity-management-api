using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace user_and_identity_management_api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AdminController : ControllerBase
    {
        [Authorize (Roles ="Admin")]
        [HttpGet("employes")]
        public IEnumerable<string>Get()
        {
            return new string[] { "Noro", "Sydney", "Jacy" };
        }
    }
}
