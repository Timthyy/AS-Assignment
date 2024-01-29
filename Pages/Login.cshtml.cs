using Assignment.Model;
using Assignment.ViewModels;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System;
using System.Security.Claims;
using System.Text;
using System.Text.RegularExpressions;

namespace Assignment.Pages
{
    public class LoginModel : PageModel
    {
		[BindProperty]
		public Login LModel { get; set; }

		private readonly SignInManager<MemberIdentityUser> signInManager;
        private readonly UserManager<MemberIdentityUser> userManager;
        private readonly ILogger<IndexModel> _logger;
        public LoginModel(ILogger<IndexModel> logger, SignInManager<MemberIdentityUser> signInManager, UserManager<MemberIdentityUser> userManager)
		{
            _logger = logger;
			this.signInManager = signInManager;
            this.userManager = userManager;
		}

		public void OnGet()
        {
        }

		public async Task<IActionResult> OnPostAsync()
		{
			if (ModelState.IsValid)
			{
                if (checkInvalidChar())
                {
                    ModelState.AddModelError("", "Invalid characters");
                }
                else
                {
                    // do sign in
                    var identityResult = await signInManager.PasswordSignInAsync(LModel.Email, LModel.Password, LModel.RememberMe, true);
                    // user is locked out
                    if (identityResult.IsLockedOut)
                    {
                        ModelState.AddModelError("", "Locked out");
                    }

                    if (identityResult.Succeeded)
				    {
                        // get logged in user
                        var loggedInUser = await userManager.FindByNameAsync(LModel.Email);
                        if (loggedInUser != null)
                        {
                            await userManager.UpdateSecurityStampAsync(loggedInUser);

                            // Add a cookie with same Guid value
                            CookieOptions options = new CookieOptions();
                            options.Secure = true;
                            options.HttpOnly = true;
                            Response.Cookies.Append("AuthCookie", loggedInUser.SecurityStamp, options);
                        }
                        return RedirectToPage("Index");
				    }
				    ModelState.AddModelError("", "Username or Password incorrect");
                }
			}
			return Page();
		}

        private bool checkInvalidChar()
        {
            if (Regex.Matches(LModel.Email, @"[*&%#$^!]").Count > 0)
            {
                return true;
            }
            return false;
        }
    }
}
