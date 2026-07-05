# TODO - AtenLana-Grid fixes

- [ ] Implement Vercel routing exclusions for `/_vercel/insights/*` and `/_vercel/speed-insights/*` in `vercel.json`
- [x] Implement Vercel routing exclusions for `/_vercel/insights/*` and `/_vercel/speed-insights/*` in `vercel.json`
- [x] Fix `/login/student` 400s by hardening form parsing (use `.get`) and aligning CSRF handling
- [ ] Redeploy / run local smoke tests to verify:
  - [ ] `/_vercel/insights/script.js` and `/_vercel/speed-insights/script.js` no longer return 404
  - [ ] `POST /login/student` succeeds for valid credentials


