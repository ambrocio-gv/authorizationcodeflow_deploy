using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace TAuthServer.Controllers
{
    public class SecretController : Controller
    {
        [Authorize]
        public string Index()
        {
            return "secret message";
        }
    }
}
