using Assignment.Model;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using System.Security.Claims;
using System.Text;

namespace Assignment.Pages
{
    [Authorize]
    [ValidateAntiForgeryToken]
    public class IndexModel : PageModel
    {
        private readonly ILogger<IndexModel> _logger;
        private UserManager<MemberIdentityUser> userManager { get; }

        private readonly SignInManager<MemberIdentityUser> signInManager;

        public IndexModel(ILogger<IndexModel> logger, UserManager<MemberIdentityUser> userManager, SignInManager<MemberIdentityUser> signInManager)
        {
            _logger = logger;
            this.userManager = userManager;
            this.signInManager = signInManager;
        }

        public async Task OnGet()
        {

            if (User != null && userManager.Users.Count() > 0)
            {
                // Log out for multiple sessions
                var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
                var user = userManager.Users.ToList().Find(t=> t.Id == userId);

                // log out user if security stamp not match cookie, WILL LOGOUT IF COOKIE IS NULL
                if (Request.Cookies["AuthCookie"] != null && user!.SecurityStamp != Request.Cookies["AuthCookie"]!.ToString())
                {
                    HttpContext.Session.Clear();
                    Response.Cookies.Delete("AuthCookie");
                    await signInManager.SignOutAsync();
                }

                var dataProtectionProvider = DataProtectionProvider.Create("EncryptData");
                var protector = dataProtectionProvider.CreateProtector("SecretKey");

                HttpContext.Session.SetString("FirstName", protector.Unprotect(decoder(user.FirstName)));
                HttpContext.Session.SetString("LastName", protector.Unprotect(decoder(user.LastName)));
                HttpContext.Session.SetString("CreditCard", protector.Unprotect(decoder(user.CreditCardNo)));
                HttpContext.Session.SetString("PhoneNumber", protector.Unprotect(decoder(user.MobileNumber)));
                HttpContext.Session.SetString("BillingAddress", protector.Unprotect(decoder(user.BillingAddress)));
                HttpContext.Session.SetString("Email", user.UserName);
                HttpContext.Session.SetString("Password", user.PasswordHash);
                HttpContext.Session.SetString("FilePath", $"uploads/{protector.Unprotect(user.ImagePath)}");

                HttpContext.Session.SetString("AuthToken", user.SecurityStamp);
            }
        }

        private string decoder(byte[] encodedBytes)
        {
            string decodedString = Encoding.ASCII.GetString(encodedBytes);

            return decodedString;
        }
    }
}