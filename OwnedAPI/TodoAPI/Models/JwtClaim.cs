using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace TodoAPI.Models
{
    public class JwtClaim
    {
        public int Id { get; set; }
        public string UserId { get; set; }
        public string Email { get; set; }
        public string Subject { get; set; }
        public string JwtId { get; set; }
        public string NotBefore { get; set; }
        public string Expiry { get; set; }
        public string IssuedAt { get; set; }
    }
}
