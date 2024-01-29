using Assignment.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Assignment.Pages
{
    public class LogoutModel : PageModel
    {
		private readonly SignInManager<MemberIdentityUser> signInManager;

		public LogoutModel(SignInManager<MemberIdentityUser> signInManager)
		{
			this.signInManager = signInManager;
		}

		public void OnGet() { }

		public async Task<IActionResult> OnPostLogoutAsync()
		{
            // clear all session
            HttpContext.Session.Clear();
			HttpContext.Session.Remove("AspNetCore.Session");
			HttpContext.Session.Remove("AspNetCore.Antiforgery");
            Response.Clear();

            Response.Cookies.Delete("AuthCookie");

            await signInManager.SignOutAsync();
			return RedirectToPage("Login");
		}
		public async Task<IActionResult> OnPostDontLogoutAsync()
		{
			return RedirectToPage("Index");
		}
	}
}
