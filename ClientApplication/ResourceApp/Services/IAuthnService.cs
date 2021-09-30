using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace ResourceApp.Services
{
    public interface IAuthnService
    {
        Task<string> GetToken();  
        
    }
}
