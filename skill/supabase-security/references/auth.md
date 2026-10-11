# Auth findings

Sections: autoconfirm, signup.

## autoconfirm
Email confirmation is off, so anyone can create unlimited accounts with fake addresses. Anything readable by `authenticated` is then effectively public, and scripts can mass-register.
Fix (user does it in the dashboard): Authentication → Sign In / Providers → Email → Confirm email on. Add CAPTCHA (Authentication → Attack Protection). Turn CAPTCHA on only after the app sends tokens, or sign-in breaks.

## signup
Open sign-up is normal for consumer apps. It just means "signed in" is not a trust boundary: policies must check ownership with `auth.uid()`. Invite-only apps can turn sign-up off.
