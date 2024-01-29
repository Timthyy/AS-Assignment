using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Assignment.Model
{
	public class AuthDbContext:IdentityDbContext<MemberIdentityUser>
	{
		private readonly IConfiguration _configuration;

		public AuthDbContext(DbContextOptions<AuthDbContext> options, IConfiguration configuration) : base(options) {
			_configuration = configuration;
		}

		protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
		{
			string connectionString = _configuration.GetConnectionString("AuthConnectionString"); optionsBuilder.UseSqlServer(connectionString);
		}
	}
}
