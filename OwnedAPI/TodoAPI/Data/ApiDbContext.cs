using TodoAPI.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;


namespace TodoAPI.Data
{
    public class ApiDbContext : DbContext
    {
        public virtual DbSet<ItemData> Items { get; set; }

        public virtual DbSet<JwtClaim> JwtClaims { get; set; }        

        public ApiDbContext(DbContextOptions<ApiDbContext> options)
            :base(options)
        {

        }




    }
}
