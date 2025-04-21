# My2FA

A MyBB two-factor authentication for added account security.

## Alpha Release

Not suggested for production use. In the meantime feedback and suggestions are welcome. Lazy to-do list:

```
- backup codes
- email method (send otp via email)

- security mail notifications on disable of a method + use of a backup code
- postgresql tables
- templates caching
- hooks
```

1. Add `{$memprofile['my2faVerificationStatus']}` in the `member_profile` template to show the verification status of
   the user in their profile.
2. Add `{$user['my2faVerificationStatus']}` in the `memberlist_user` template to show the verification status of the use
   in the member list.
3. Add `{$post['my2faVerificationStatus']}` in the `postbit` or `postbit_classic` template to show the verification
   status of the user in their posts.